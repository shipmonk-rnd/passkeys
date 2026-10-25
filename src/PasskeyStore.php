<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys;

use ShipMonk\Passkeys\Ceremony\AuthenticationResult;
use ShipMonk\Passkeys\Ceremony\CredentialRecord;
use ShipMonk\Passkeys\Ceremony\CredentialStore;
use ShipMonk\Passkeys\Options\PublicKeyCredentialUserEntity;

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
     * `excludeCredentials` and to enforce the former at verification. The handle can belong to no
     * account: when a two-step login names an unknown username, the flow pins the ceremony to a
     * fresh {@see PasskeyFlow::generateUserHandle()} value and looks that up. Return an empty list
     * for it and never throw — a failure only for unknown usernames would tell them apart. If your
     * handles have a fixed format, override {@see PasskeyFlow::generateUserHandle()} to match it.
     *
     * @param string $userHandle raw user handle bytes
     * @return list<CredentialRecord>
     */
    public function findCredentialsByUserHandle(string $userHandle): array;

    /**
     * The account's current identity (user handle, username, display name) as a
     * {@see PublicKeyCredentialUserEntity}, or null when no such account exists. Used to build a
     * {@see \ShipMonk\Passkeys\Signal\CurrentUserDetailsSignal}; typically the same lookup that
     * backs your login/profile pages, keyed by the opaque handle rather than the username.
     *
     * The returned entity's `id` is authoritative for the signal and is expected to equal the
     * queried handle (both are the same user handle bytes).
     *
     * @param string $userHandle raw user handle bytes
     */
    public function findUserEntityByUserHandle(string $userHandle): ?PublicKeyCredentialUserEntity;

    /**
     * Persists the newly registered credential — typically one INSERT of
     * {@see RegisteredPasskey::toCredentialRecord()}, plus whatever extra columns you keep
     * ({@see RegisteredPasskey::$authenticatorAttachment}, a created-at timestamp, a label…).
     */
    public function saveCredential(RegisteredPasskey $passkey): void;

    /**
     * Persists the new credential state after a successful assertion — {@see AuthenticationResult}
     * spells out which fields to copy onto the record — and is where you can act on
     * {@see AuthenticationResult::$possibleClone}.
     */
    public function updateCredential(AuthenticationResult $result): void;

}
