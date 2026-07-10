<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Testing;

use OpenSSLAsymmetricKey;
use ShipMonk\WebAuthn\Cose\CoseAlgorithmIdentifier;

/**
 * A credential held by a {@see FakeAuthenticator}: the state a real authenticator keeps per
 * passkey, exposed so tests can assert against it (or mess with it — e.g. sign with the private
 * key directly to build a tampered response).
 *
 * @api
 */
final class FakePasskey
{

    /**
     * @param string                     $credentialId raw credential id bytes
     * @param string                     $rpId         the RP ID the passkey is scoped to
     * @param string                     $userHandle   raw user handle bytes of the account it was created for
     * @param CoseAlgorithmIdentifier::* $algorithm    the COSE algorithm of the key pair
     * @param OpenSSLAsymmetricKey       $privateKey   the signing key; its public half was attested at creation
     * @param int                        $signCount    the current signature counter, incremented by each assertion
     */
    public function __construct(
        public readonly string $credentialId,
        public readonly string $rpId,
        public readonly string $userHandle,
        public readonly int $algorithm,
        public readonly OpenSSLAsymmetricKey $privateKey,
        public private(set) int $signCount = 0,
    )
    {
    }

    /**
     * Increments and returns the signature counter, as a real authenticator does for each assertion.
     */
    public function nextSignCount(): int
    {
        return ++$this->signCount;
    }

}
