<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;
use WebAuthnX\Cose\CoseKey;

use function array_key_exists;
use function base64_decode;
use function base64_encode;

/**
 * Credential store for the demo, deliberately shaped like the database a real relying party would
 * use: two "tables" of rows, each row an associative array of "columns" holding only portable
 * scalar values — exactly what you would map to SQL columns.
 *
 *   table `users`        — user_handle (PK), name
 *   table `credentials`  — credential_id (PK), user_handle (FK), public_key, sign_count,
 *                          uv_initialized, backup_eligible, backup_state, transports
 *
 * The `public_key` column is the credential's key serialised with {@see CoseKey::toBytes()} — a
 * single BLOB/TEXT column — and rehydrated on read with {@see CoseKey::fromBytes()}. Binary ids and
 * keys are base64-encoded so every column is a plain string/int/bool.
 *
 * The rows live in $_SESSION only because PHP's built-in server runs each request in a fresh
 * process, so plain in-process memory cannot survive between the register and login requests. There
 * is no file or database of our own here; in production you would run INSERT / SELECT / UPDATE
 * against these same columns instead.
 */
final class PasskeyStore implements CredentialStore
{
	public function __construct()
	{
		$_SESSION['users'] ??= [];
		$_SESSION['credentials'] ??= [];
	}

	// -- credentials table --------------------------------------------------------------------

	public function findByCredentialId(Bytes $credentialId): ?CredentialRecord
	{
		// SELECT * FROM credentials WHERE credential_id = ?
		$row = $_SESSION['credentials'][base64_encode($credentialId->toBinaryString())] ?? null;

		if ($row === null) {
			return null;
		}

		return new CredentialRecord(
			credentialId: $credentialId,
			publicKey: CoseKey::fromBytes(Bytes::fromBinaryString(base64_decode($row['public_key']))),
			signCount: $row['sign_count'],
			userHandle: Bytes::fromBinaryString(base64_decode($row['user_handle'])),
			uvInitialized: $row['uv_initialized'],
			backupEligible: $row['backup_eligible'],
			backupState: $row['backup_state'],
			transports: $row['transports'],
		);
	}

	public function insertCredential(CredentialRecord $record): void
	{
		// INSERT INTO credentials (...) VALUES (...)
		$credentialId = base64_encode($record->credentialId->toBinaryString());

		$_SESSION['credentials'][$credentialId] = [
			'credential_id' => $credentialId,
			'user_handle' => base64_encode($record->userHandle->toBinaryString()),
			'public_key' => base64_encode($record->publicKey->toBytes()->toBinaryString()),
			'sign_count' => $record->signCount,
			'uv_initialized' => $record->uvInitialized,
			'backup_eligible' => $record->backupEligible,
			'backup_state' => $record->backupState,
			'transports' => $record->transports, // list<string>|null — a DB would hold this as JSON
		];
	}

	public function updateSignCount(Bytes $credentialId, int $newSignCount): void
	{
		// UPDATE credentials SET sign_count = ? WHERE credential_id = ?
		$key = base64_encode($credentialId->toBinaryString());

		if (array_key_exists($key, $_SESSION['credentials'])) {
			$_SESSION['credentials'][$key]['sign_count'] = $newSignCount;
		}
	}

	// -- users table --------------------------------------------------------------------------

	public function insertUser(Bytes $handle, string $name): void
	{
		// INSERT INTO users (user_handle, name) VALUES (?, ?)
		$userHandle = base64_encode($handle->toBinaryString());
		$_SESSION['users'][$userHandle] = ['user_handle' => $userHandle, 'name' => $name];
	}

	/**
	 * The single demo account, or null before the first registration.
	 *
	 * @return array{user_handle: string, name: string}|null
	 */
	public function user(): ?array
	{
		// SELECT * FROM users LIMIT 1
		foreach ($_SESSION['users'] as $row) {
			return $row;
		}

		return null;
	}

	public function userNameForHandle(Bytes $handle): ?string
	{
		// SELECT name FROM users WHERE user_handle = ?
		return $_SESSION['users'][base64_encode($handle->toBinaryString())]['name'] ?? null;
	}

	// -- pending ceremony challenge -----------------------------------------------------------
	// Not a table: transient per-user state that belongs in the session (or a short-lived cache).

	public function rememberChallenge(Bytes $challenge): void
	{
		$_SESSION['pending_challenge'] = base64_encode($challenge->toBinaryString());
	}

	/** Returns and clears the pending challenge, keeping each challenge single-use. */
	public function consumeChallenge(): ?Bytes
	{
		$challenge = $_SESSION['pending_challenge'] ?? null;
		unset($_SESSION['pending_challenge']);

		return $challenge === null ? null : Bytes::fromBinaryString(base64_decode($challenge));
	}
}
