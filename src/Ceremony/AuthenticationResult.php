<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Ceremony;

/**
 * The outcome of a successful authentication ceremony (WebAuthn §7.2). Reaching this object means
 * the assertion signature verified and every mandated check passed; the caller should now persist
 * the new state on the credential record: set `signCount` to {@see $newSignCount}, `backupState`
 * to {@see $backupState}, and — if it was not already — `uvInitialized` to {@see $userVerified}.
 *
 * @api
 */
final readonly class AuthenticationResult
{

    /**
     * @param string $credentialId  raw credential id bytes of the credential that signed the assertion
     * @param string $userHandle    raw user handle bytes from the located credential record
     * @param int    $newSignCount  the counter reported by the authenticator, to store on the record
     * @param bool   $userVerified  whether the UV flag was set on this assertion
     * @param bool   $backupState   the credential's current backup state (may legitimately change over time)
     * @param bool   $possibleClone set when the sign counter did not strictly increase (§7.2 step 22): a
     *       signal — not proof — that the credential may be cloned. The caller decides how to react; the
     *       ceremony itself does not fail on it.
     */
    public function __construct(
        public string $credentialId,
        public string $userHandle,
        public int $newSignCount,
        public bool $userVerified,
        public bool $backupState,
        public bool $possibleClone,
    )
    {
    }

}
