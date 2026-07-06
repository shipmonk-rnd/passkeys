<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use PDO;
use PDOStatement;
use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Passkey\PasskeyStore as PasskeyStoreInterface;
use WebAuthnX\Passkey\RegisteredPasskey;

use function array_map;
use function base64_decode;
use function base64_encode;
use function date;
use function json_decode;
use function json_encode;
use function random_bytes;

use const JSON_THROW_ON_ERROR;

/**
 * The demo's database: a SQLite file (pdo_sqlite), so accounts and passkeys survive server
 * restarts. It implements the library's {@see PasskeyStoreInterface PasskeyStore} — the durable
 * storage a {@see \WebAuthnX\Passkey\PasskeyFlow} runs against — plus the account methods the
 * demo's own endpoints need (insertUser, findUserByEmail, …). One user (identified by email) has
 * many credentials (a user_id foreign key):
 *
 *   table `users`        — id (integer PK), passkey_user_handle (BLOB, unique), email (unique)
 *   table `credentials`  — credential_id (PK, base64), user_id (FK),
 *                          public_key (base64 of CoseKey::toBytes()), sign_count,
 *                          uv_initialized, backup_eligible, backup_state, transports,
 *                          authenticator_attachment, created_at
 *
 * The primary key is a plain integer id, as in a real schema; the WebAuthn user handle is a
 * separate value — the spec-recommended 64 opaque random bytes — in its own unique BLOB column,
 * generated once per user by {@see insertUser()}. Relations go through the integer id
 * (credentials.user_id); the handle only crosses the wire in ceremonies and is joined back in when
 * a {@see CredentialRecord} is hydrated. Handle parameters are bound as PDO::PARAM_LOB — a PHP
 * string binds as text by default, and in SQLite a TEXT value never compares equal to a BLOB.
 *
 * The public key is a single column via {@see CoseKey::toBytes()}, rehydrated on read with
 * {@see CoseKey::fromBytes()} — persistence is plain INSERT / SELECT / UPDATE, the same statements
 * a production relying party would run against its own database.
 */
final class PasskeyStore implements PasskeyStoreInterface
{
    private readonly PDO $db;

    public function __construct(string $databaseFile)
    {
        $this->db = new PDO('sqlite:' . $databaseFile, options: [
            PDO::ATTR_TIMEOUT => 5,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $this->db->exec('
			CREATE TABLE IF NOT EXISTS users (
				id                  INTEGER PRIMARY KEY,
				passkey_user_handle BLOB NOT NULL UNIQUE,
				email               TEXT NOT NULL UNIQUE
			);

			CREATE TABLE IF NOT EXISTS credentials (
				credential_id            TEXT PRIMARY KEY,
				user_id                  INTEGER NOT NULL REFERENCES users (id),
				public_key               TEXT NOT NULL,
				sign_count               INTEGER NOT NULL,
				uv_initialized           INTEGER NOT NULL,
				backup_eligible          INTEGER NOT NULL,
				backup_state             INTEGER NOT NULL,
				transports               TEXT,
				authenticator_attachment TEXT,
				created_at               TEXT NOT NULL
			);
		');
    }

    // -- users table --------------------------------------------------------------------------

    /**
     * @return array{id: int, passkey_user_handle: string, email: string}
     */
    public function insertUser(string $email): array
    {
        $handle = random_bytes(64); // The spec-recommended user handle: 64 opaque random bytes, unrelated to the primary key.

        $statement = $this->db->prepare('INSERT INTO users (passkey_user_handle, email) VALUES (:handle, :email)');
        $this->bindParameter($statement, ':handle', $handle, PDO::PARAM_LOB);
        $this->bindParameter($statement, ':email', $email);
        $statement->execute();

        return ['id' => (int) $this->db->lastInsertId(), 'passkey_user_handle' => $handle, 'email' => $email];
    }

    /**
     * @return array{id: int, passkey_user_handle: string, email: string}|null
     */
    public function findUserByEmail(string $email): ?array
    {
        $statement = $this->db->prepare('SELECT * FROM users WHERE email = :email');
        $this->bindParameter($statement, ':email', $email);
        $statement->execute();

        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    /**
     * @return array{id: int, passkey_user_handle: string, email: string}|null
     */
    public function findUserById(int $id): ?array
    {
        $statement = $this->db->prepare('SELECT * FROM users WHERE id = :id');
        $this->bindParameter($statement, ':id', $id, PDO::PARAM_INT);
        $statement->execute();

        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    /**
     * @return array{id: int, passkey_user_handle: string, email: string}|null
     */
    public function findUserByHandle(string $userHandle): ?array
    {
        $statement = $this->db->prepare('SELECT * FROM users WHERE passkey_user_handle = :handle');
        $this->bindParameter($statement, ':handle', $userHandle, PDO::PARAM_LOB);
        $statement->execute();

        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    public function findUserHandleByUsername(string $username): ?string
    {
        // The demo's usernames are emails.
        return $this->findUserByEmail($username)['passkey_user_handle'] ?? null;
    }

    // -- credentials table --------------------------------------------------------------------

    public function findCredentialByCredentialId(string $credentialId): ?CredentialRecord
    {
        $encodedCredentialId = base64_encode($credentialId);

        $statement = $this->db->prepare('
			SELECT credentials.*, users.passkey_user_handle
			FROM credentials
			JOIN users ON users.id = credentials.user_id
			WHERE credential_id = :credential_id
		');

        $this->bindParameter($statement, ':credential_id', $encodedCredentialId);
        $statement->execute();

        $row = $statement->fetch();
        return $row === false ? null : $this->recordFromRow($row);
    }

    /**
     * @return list<CredentialRecord>
     */
    public function findCredentialsByUserHandle(string $userHandle): array
    {
        $statement = $this->db->prepare('
			SELECT credentials.*, users.passkey_user_handle
			FROM credentials
			JOIN users ON users.id = credentials.user_id
			WHERE users.passkey_user_handle = :handle
			ORDER BY created_at
		');

        $this->bindParameter($statement, ':handle', $userHandle, PDO::PARAM_LOB);
        $statement->execute();

        return array_map($this->recordFromRow(...), $statement->fetchAll());
    }

    public function saveCredential(RegisteredPasskey $passkey): void
    {
        $record = $passkey->toCredentialRecord();

        $statement = $this->db->prepare('
			INSERT INTO credentials (
				credential_id, user_id, public_key, sign_count, uv_initialized,
				backup_eligible, backup_state, transports, authenticator_attachment, created_at
			) VALUES (
				:credential_id, (SELECT id FROM users WHERE passkey_user_handle = :user_handle),
				:public_key, :sign_count, :uv_initialized, :backup_eligible, :backup_state,
				:transports, :authenticator_attachment, :created_at
			)
		');

        $this->bindParameter($statement, ':credential_id', base64_encode($record->credentialId));
        $this->bindParameter($statement, ':user_handle', $record->userHandle, PDO::PARAM_LOB);
        $this->bindParameter($statement, ':public_key', base64_encode($record->publicKey->toBytes()));
        $this->bindParameter($statement, ':sign_count', $record->signCount, PDO::PARAM_INT);
        $this->bindParameter($statement, ':uv_initialized', (int) $record->uvInitialized, PDO::PARAM_INT);
        $this->bindParameter($statement, ':backup_eligible', (int) $record->backupEligible, PDO::PARAM_INT);
        $this->bindParameter($statement, ':backup_state', (int) $record->backupState, PDO::PARAM_INT);
        $this->bindParameter($statement, ':transports', $record->transports === null ? null : json_encode($record->transports, JSON_THROW_ON_ERROR));
        $this->bindParameter($statement, ':authenticator_attachment', $passkey->authenticatorAttachment?->value);
        $this->bindParameter($statement, ':created_at', date('c'));

        $statement->execute();
    }

    public function updateCredential(AuthenticationResult $result): void
    {
        // A real relying party could additionally alert on $result->possibleClone.
        $credentialId = base64_encode($result->credentialId);
        $signCount = $result->newSignCount;
        $backupState = (int) $result->backupState;
        $uvInitialized = (int) $result->userVerified;

        $statement = $this->db->prepare('
			UPDATE credentials
			SET sign_count = :sign_count,
				backup_state = :backup_state,
				uv_initialized = max(uv_initialized, :uv_initialized)
			WHERE credential_id = :credential_id
		');

        $this->bindParameter($statement, ':sign_count', $signCount, PDO::PARAM_INT);
        $this->bindParameter($statement, ':backup_state', $backupState, PDO::PARAM_INT);
        $this->bindParameter($statement, ':uv_initialized', $uvInitialized, PDO::PARAM_INT);
        $this->bindParameter($statement, ':credential_id', $credentialId);

        $statement->execute();
    }

    /**
     * Every credential registered to a user, as raw rows — for the demo's passkey list and its
     * "does this account have any passkeys yet" checks.
     *
     * @return list<array<string, mixed>>
     */
    public function credentialsForUser(int $userId): array
    {
        $statement = $this->db->prepare('SELECT * FROM credentials WHERE user_id = :user_id ORDER BY created_at');
        $this->bindParameter($statement, ':user_id', $userId, PDO::PARAM_INT);
        $statement->execute();

        return $statement->fetchAll();
    }

    /**
     * @param array<string, mixed> $row
     */
    private function recordFromRow(array $row): CredentialRecord
    {
        return new CredentialRecord(
            credentialId: base64_decode($row['credential_id']),
            publicKey: CoseKey::fromBytes(base64_decode($row['public_key'])),
            signCount: $row['sign_count'],
            userHandle: $row['passkey_user_handle'],
            uvInitialized: (bool) $row['uv_initialized'],
            backupEligible: (bool) $row['backup_eligible'],
            backupState: (bool) $row['backup_state'],
            transports: $row['transports'] === null ? null : json_decode($row['transports'], flags: JSON_THROW_ON_ERROR),
        );
    }

    private function bindParameter(PDOStatement $statement, string $parameterName, mixed $value, int $type = PDO::PARAM_STR): void
    {
        $statement->bindValue($parameterName, $value, $type);
    }
}
