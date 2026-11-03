<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Ceremony;

use ShipMonk\Passkeys\Cose\CoseKey;

/**
 * The persistent state a relying party stores for a registered credential, as described by the
 * {@link https://www.w3.org/TR/webauthn-3/#credential-record credential record} in WebAuthn §7.1
 * step 27. The library never persists this itself — the caller stores it after a successful
 * registration (see {@see RegistrationResult::toCredentialRecord()}) and hands it back, looked
 * up via a {@see CredentialStore}, on each authentication.
 *
 * @api
 */
final class CredentialRecord
{

    /**
     * @param string            $credentialId raw credential id bytes
     * @param string            $userHandle   raw user handle bytes
     * @param list<string>|null $transports   as reported by the client at registration
     */
    public function __construct(
        public readonly string $credentialId,
        public readonly CoseKey $publicKey,
        public readonly int $signCount,
        public readonly string $userHandle,
        public readonly bool $uvInitialized,
        public readonly bool $backupEligible,
        public readonly bool $backupState,
        public readonly ?array $transports = null,
    )
    {
    }

}
