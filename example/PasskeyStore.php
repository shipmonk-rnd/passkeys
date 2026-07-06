<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Enum\AuthenticatorAttachment;

use function array_key_exists;
use function array_values;
use function base64_decode;
use function base64_encode;
use function date;

/**
 * The demo's "database", deliberately shaped like the SQL tables a real relying party would use.
 * Each array is a table, each row an associative array of scalar columns — exactly what you would
 * map to SQL. One user (identified by email) has many credentials (a user_handle foreign key):
 *
 *   table `users`        — user_handle (PK, base64), email (unique)
 *   table `credentials`  — credential_id (PK, base64), user_handle (FK, base64),
 *                          public_key (base64 of CoseKey::toBytes()), sign_count,
 *                          uv_initialized, backup_eligible, backup_state, transports,
 *                          authenticator_attachment, created_at
 *
 * The public key is a single column via {@see CoseKey::toBytes()}, rehydrated on read with
 * {@see CoseKey::fromBytes()}. Rows live in $_SESSION only because PHP's built-in server runs each
 * request in a fresh process; there is no file/database of our own — in production you would run
 * INSERT / SELECT / UPDATE against these same columns.
 */
final class PasskeyStore implements CredentialStore
{
	public function __construct()
	{
		$_SESSION['users'] ??= [];
		$_SESSION['credentials'] ??= [];
	}

	// -- users table --------------------------------------------------------------------------

	public function insertUser(string $handle, string $email): void
	{
		// INSERT INTO users (user_handle, email) VALUES (?, ?)
		$userHandle = base64_encode($handle);
		$_SESSION['users'][$userHandle] = ['user_handle' => $userHandle, 'email' => $email];
	}

	/**
	 * @return array{user_handle: string, email: string}|null
	 */
	public function findUserByEmail(string $email): ?array
	{
		// SELECT * FROM users WHERE email = ?
		foreach ($_SESSION['users'] as $row) {
			if ($row['email'] === $email) {
				return $row;
			}
		}

		return null;
	}

	/**
	 * @return array{user_handle: string, email: string}|null
	 */
	public function findUserByHandle(string $handle): ?array
	{
		// SELECT * FROM users WHERE user_handle = ?
		return $_SESSION['users'][base64_encode($handle)] ?? null;
	}

	// -- credentials table --------------------------------------------------------------------

	public function findByCredentialId(string $credentialId): ?CredentialRecord
	{
		// SELECT * FROM credentials WHERE credential_id = ?
		$row = $_SESSION['credentials'][base64_encode($credentialId)] ?? null;

		if ($row === null) {
			return null;
		}

		return new CredentialRecord(
			credentialId: $credentialId,
			publicKey: CoseKey::fromBytes(base64_decode($row['public_key'])),
			signCount: $row['sign_count'],
			userHandle: base64_decode($row['user_handle']),
			uvInitialized: $row['uv_initialized'],
			backupEligible: $row['backup_eligible'],
			backupState: $row['backup_state'],
			transports: $row['transports'],
		);
	}

	public function insertCredential(CredentialRecord $record, ?AuthenticatorAttachment $authenticatorAttachment): void
	{
		// INSERT INTO credentials (...) VALUES (...)
		$credentialId = base64_encode($record->credentialId);

		$_SESSION['credentials'][$credentialId] = [
			'credential_id' => $credentialId,
			'user_handle' => base64_encode($record->userHandle),
			'public_key' => base64_encode($record->publicKey->toBytes()),
			'sign_count' => $record->signCount,
			'uv_initialized' => $record->uvInitialized,
			'backup_eligible' => $record->backupEligible,
			'backup_state' => $record->backupState,
			'transports' => $record->transports, // list<string>|null — a DB would hold this as JSON
			'authenticator_attachment' => $authenticatorAttachment?->value,
			'created_at' => date('c'),
		];
	}

	public function updateSignCount(string $credentialId, int $newSignCount): void
	{
		// UPDATE credentials SET sign_count = ? WHERE credential_id = ?
		$key = base64_encode($credentialId);

		if (array_key_exists($key, $_SESSION['credentials'])) {
			$_SESSION['credentials'][$key]['sign_count'] = $newSignCount;
		}
	}

	/**
	 * Every credential registered to a user — for excluding already-registered authenticators at
	 * registration and for listing a user's passkeys.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function credentialsForUser(string $handle): array
	{
		// SELECT * FROM credentials WHERE user_handle = ?
		$userHandle = base64_encode($handle);
		$rows = [];

		foreach ($_SESSION['credentials'] as $row) {
			if ($row['user_handle'] === $userHandle) {
				$rows[] = $row;
			}
		}

		return array_values($rows);
	}
}
