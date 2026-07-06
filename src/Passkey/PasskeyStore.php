<?php declare(strict_types = 1);

namespace WebAuthnX\Passkey;

use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;

/**
 * The relying party's durable passkey storage behind a {@see PasskeyFlow} — the user and
 * credential tables — extending the ceremony-level {@see CredentialStore} with the lookups and
 * writes the flow needs. Typically implemented once per application as a thin repository over the
 * same database that holds your users.
 *
 * Keep it separate from the transient {@see PendingCeremonyStore}: this store outlives sessions,
 * that one must not.
 *
 * @api
 */
interface PasskeyStore extends CredentialStore
{
	/**
	 * Maps a login-form identifier (email/username) to the account's user handle, or null when no
	 * such account exists. Only consulted for the two-step flow.
	 *
	 * @return string|null raw user handle bytes
	 */
	public function findUserHandleByUsername(string $username): ?string;

	/**
	 * Every credential registered to the given account — used to build `allowCredentials` /
	 * `excludeCredentials` and to enforce the former at verification.
	 *
	 * @param  string $userHandle raw user handle bytes
	 * @return list<CredentialRecord>
	 */
	public function findCredentialsByUserHandle(string $userHandle): array;

	/**
	 * Persists the newly registered credential — typically one INSERT of
	 * {@see RegisteredPasskey::toCredentialRecord()}, plus whatever extra columns you keep
	 * ({@see RegisteredPasskey::$authenticatorAttachment}, a created-at timestamp, a label…).
	 */
	public function saveCredential(RegisteredPasskey $passkey): void;

	/**
	 * Persists the post-authentication credential state: set the record's `signCount` to
	 * {@see AuthenticationResult::$newSignCount}, `backupState` to {@see AuthenticationResult::$backupState},
	 * and — if it was not already — `uvInitialized` to {@see AuthenticationResult::$userVerified}.
	 * This is also the place to react to {@see AuthenticationResult::$possibleClone} if you want to.
	 */
	public function updateCredential(AuthenticationResult $result): void;
}
