<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Ceremony;

use ShipMonk\WebAuthn\Cose\CoseKey;

/**
 * The persistent state a relying party stores for a registered credential, as described by the
 * {@link https://w3c.github.io/webauthn/#credential-record credential record} in WebAuthn §7.1
 * step 27. The library never persists this itself — the caller stores it after a successful
 * registration (see {@see RegistrationResult::toCredentialRecord()}) and hands it back, looked
 * up via a {@see CredentialStore}, on each authentication.
 *
 * @api
 */
final readonly class CredentialRecord
{

    /**
     * @param string            $credentialId raw credential id bytes
     * @param string            $userHandle   raw user handle bytes
     * @param list<string>|null $transports   as reported by the client at registration
     */
    public function __construct(
        public string $credentialId,
        public CoseKey $publicKey,
        public int $signCount,
        public string $userHandle,
        public bool $uvInitialized,
        public bool $backupEligible,
        public bool $backupState,
        public ?array $transports = null,
    )
    {
    }

}
