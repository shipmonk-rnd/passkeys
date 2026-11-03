<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Testing;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;

/**
 * A credential held by a {@see FakeAuthenticator}: the state a real authenticator keeps per
 * passkey, exposed so tests can assert against it (or mess with it — e.g. sign with the private
 * key directly to build a tampered response).
 *
 * Before PHP 8.4, ext-openssl cannot sign with an EdDSA (Ed25519) private key. To sign with one
 * there, export it with {@see \openssl_pkey_export()}: its PKCS#8 DER ends with the 32-byte seed,
 * which {@see \sodium_crypto_sign_seed_keypair()} turns into the secret key for
 * {@see \sodium_crypto_sign_detached()}.
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
        private int $signCount = 0,
    )
    {
    }

    /**
     * The current signature counter: 0 for a passkey that has not asserted yet, incremented by each assertion.
     */
    public function getSignCount(): int
    {
        return $this->signCount;
    }

    /**
     * Increments and returns the signature counter, as a real authenticator does for each assertion.
     */
    public function nextSignCount(): int
    {
        return ++$this->signCount;
    }

}
