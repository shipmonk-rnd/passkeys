<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use LogicException;
use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use function in_array;
use function is_string;
use function ltrim;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_pkey_new;
use function ord;
use function strlen;
use function substr;
use const OPENSSL_ALGO_SHA256;

/**
 * COSE key of type RSA, e.g. RS256.
 *
 * @extends CoseKey<value-of<self::ALGORITHMS>>
 *
 * @see https://www.rfc-editor.org/rfc/rfc8230.html#section-4 RSA key parameters
 * @api
 */
final readonly class CoseRsaKey extends CoseKey
{

    /**
     * Key type value for RSA keys.
     */
    public const int KTY = 3;

    /**
     * RSA key label: modulus (n).
     */
    public const int LABEL_N = -1;

    /**
     * RSA key label: public exponent (e).
     */
    public const int LABEL_E = -2;

    /**
     * Algorithms that use an RSA key.
     */
    private const array ALGORITHMS = [
        CoseAlgorithmIdentifier::RS256,
    ];

    /**
     * Minimum accepted modulus size in bytes (2048 bits; RFC 8230 §6.1).
     */
    private const int MIN_MODULUS_BYTES = 256;

    /**
     * @param value-of<self::ALGORITHMS> $alg
     * @param string                     $n   modulus as raw big-endian bytes
     * @param string                     $e   public exponent as raw big-endian bytes
     */
    private function __construct(
        int $alg,
        public string $n,
        public string $e,
    )
    {
        parent::__construct($alg);
    }

    /**
     * @throws CborMapException
     * @throws CoseKeyException
     */
    public static function fromCborMap(CborMap $map): self
    {
        $alg = $map->getInt(self::LABEL_ALG);
        $n = $map->getString(self::LABEL_N);
        $e = $map->getString(self::LABEL_E);

        if (!in_array($alg, self::ALGORITHMS, true)) {
            throw new CoseKeyException("Unsupported RSA algorithm {$alg}");
        }

        $modulus = ltrim($n, "\x00");

        if (strlen($modulus) < self::MIN_MODULUS_BYTES) {
            throw new CoseKeyException('RSA modulus must be at least 2048 bits');
        }

        // A public exponent of 1 makes verification the identity function, so the
        // PKCS#1 encoded message can be presented as the signature and "verifies"
        // without the private key. Even exponents are likewise invalid for RSA.
        $exponent = ltrim($e, "\x00");

        if ($exponent === '' || $exponent === "\x01" || (ord(substr($exponent, -1)) & 1) === 0) {
            throw new CoseKeyException('RSA public exponent must be an odd integer greater than 1');
        }

        return new self($alg, $n, $e);
    }

    public function toBytes(): string
    {
        return CborEncoder::encodeMap([
            [CborEncoder::encodeInt(self::LABEL_KTY), CborEncoder::encodeInt(self::KTY)],
            [CborEncoder::encodeInt(self::LABEL_ALG), CborEncoder::encodeInt($this->alg)],
            [CborEncoder::encodeInt(self::LABEL_N), CborEncoder::encodeByteString($this->n)],
            [CborEncoder::encodeInt(self::LABEL_E), CborEncoder::encodeByteString($this->e)],
        ]);
    }

    protected function toOpenSslPublicKey(): OpenSSLAsymmetricKey|false
    {
        // Unlike EC2 and OKP, openssl_pkey_new() cannot build a public-only RSA key: it
        // requires a private exponent d and always flags the result private, which
        // openssl_verify() then refuses. So build a throwaway key with an empty, unused d
        // (openssl_pkey_new() only requires d to be present; solely n and e feed the
        // exported public key) and hand OpenSSL's own re-exported public key to
        // openssl_pkey_get_public(), which yields a usable public key.
        $throwawayKey = openssl_pkey_new([
            'rsa' => [
                'n' => $this->n,
                'e' => $this->e,
                'd' => '',
            ],
        ]);

        if ($throwawayKey === false) {
            throw new LogicException('openssl_pkey_new() unexpectedly failed to build an RSA key');
        }

        $details = openssl_pkey_get_details($throwawayKey);
        $publicKeyPem = $details === false ? null : ($details['key'] ?? null);

        if (!is_string($publicKeyPem)) {
            throw new LogicException('Failed to export the public key of a freshly built RSA key');
        }

        return openssl_pkey_get_public($publicKeyPem);
    }

    protected function getOpenSslAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256; // RS256 is the only supported RSA algorithm
    }

}
