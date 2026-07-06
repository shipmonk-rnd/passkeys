<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use PDO;
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
		// The spec-recommended user handle: 64 opaque random bytes, unrelated to the primary key.
		$handle = random_bytes(64);

		$statement = $this->db->prepare('INSERT INTO users (passkey_user_handle, email) VALUES (:handle, :email)');
		$statement->bindParam(':handle', $handle, PDO::PARAM_LOB);
		$statement->bindParam(':email', $email);
		$statement->execute();

		return ['id' => (int) $this->db->lastInsertId(), 'passkey_user_handle' => $handle, 'email' => $email];
	}

	/**
	 * @return array{id: int, passkey_user_handle: string, email: string}|null
	 */
	public function findUserByEmail(string $email): ?array
	{
		$statement = $this->db->prepare('SELECT * FROM users WHERE email = :email');
		$statement->bindParam(':email', $email);
		$statement->execute();
		$row = $statement->fetch();

		/** @var array{id: int, passkey_user_handle: string, email: string}|null */
		return $row === false ? null : $row;
	}

	/**
	 * @return array{id: int, passkey_user_handle: string, email: string}|null
	 */
	public function findUserById(int $id): ?array
	{
		$statement = $this->db->prepare('SELECT * FROM users WHERE id = :id');
		$statement->bindParam(':id', $id, PDO::PARAM_INT);
		$statement->execute();
		$row = $statement->fetch();

		/** @var array{id: int, passkey_user_handle: string, email: string}|null */
		return $row === false ? null : $row;
	}

	/**
	 * @return array{id: int, passkey_user_handle: string, email: string}|null
	 */
	public function findUserByHandle(string $passkeyUserHandle): ?array
	{
		$statement = $this->db->prepare('SELECT * FROM users WHERE passkey_user_handle = :handle');
		$statement->bindParam(':handle', $passkeyUserHandle, PDO::PARAM_LOB);
		$statement->execute();
		$row = $statement->fetch();

		/** @var array{id: int, passkey_user_handle: string, email: string}|null */
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
		$statement->bindParam(':credential_id', $encodedCredentialId);
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
		$statement->bindParam(':handle', $userHandle, PDO::PARAM_LOB);
		$statement->execute();

		return array_map($this->recordFromRow(...), $statement->fetchAll());
	}

	public function saveCredential(RegisteredPasskey $passkey): void
	{
		$record = $passkey->toCredentialRecord();

		$credentialId = base64_encode($record->credentialId);
		$userHandle = $record->userHandle;
		$publicKey = base64_encode($record->publicKey->toBytes());
		$signCount = $record->signCount;
		$uvInitialized = (int) $record->uvInitialized;
		$backupEligible = (int) $record->backupEligible;
		$backupState = (int) $record->backupState;
		$transports = $record->transports === null ? null : json_encode($record->transports, JSON_THROW_ON_ERROR);
		$attachment = $passkey->authenticatorAttachment?->value;
		$createdAt = date('c');

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

		$statement->bindParam(':credential_id', $credentialId);
		$statement->bindParam(':user_handle', $userHandle, PDO::PARAM_LOB);
		$statement->bindParam(':public_key', $publicKey);
		$statement->bindParam(':sign_count', $signCount, PDO::PARAM_INT);
		$statement->bindParam(':uv_initialized', $uvInitialized, PDO::PARAM_INT);
		$statement->bindParam(':backup_eligible', $backupEligible, PDO::PARAM_INT);
		$statement->bindParam(':backup_state', $backupState, PDO::PARAM_INT);
		$statement->bindParam(':transports', $transports);
		$statement->bindParam(':authenticator_attachment', $attachment);
		$statement->bindParam(':created_at', $createdAt);
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
		$statement->bindParam(':sign_count', $signCount, PDO::PARAM_INT);
		$statement->bindParam(':backup_state', $backupState, PDO::PARAM_INT);
		$statement->bindParam(':uv_initialized', $uvInitialized, PDO::PARAM_INT);
		$statement->bindParam(':credential_id', $credentialId);
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
		$statement->bindParam(':user_id', $userId, PDO::PARAM_INT);
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
}
