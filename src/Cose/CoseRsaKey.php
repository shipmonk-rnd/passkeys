<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use ShipMonk\Passkeys\Der\DerEncoder;
use function in_array;
use function ltrim;
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
final class CoseRsaKey extends CoseKey
{

    /**
     * Key type value for RSA keys.
     */
    public const KTY = 3;

    /**
     * RSA key label: modulus (n).
     */
    public const LABEL_N = -1;

    /**
     * RSA key label: public exponent (e).
     */
    public const LABEL_E = -2;

    /**
     * OID for rsaEncryption (RFC 8017 App. C / RFC 3279 §2.3.1).
     */
    private const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

    /**
     * Algorithms that use an RSA key.
     */
    private const ALGORITHMS = [
        CoseAlgorithmIdentifier::RS256,
    ];

    /**
     * Minimum accepted modulus size in bytes (2048 bits; RFC 8230 §6.1).
     */
    private const MIN_MODULUS_BYTES = 256;

    /**
     * Maximum accepted modulus size in bytes (8192 bits). A "none"-format registration stores
     * the key without any signature proving possession, so without a ceiling an enrollee could
     * persist an oversized modulus that makes every later verification disproportionately slow.
     */
    private const MAX_MODULUS_BYTES = 1_024;

    /**
     * Maximum accepted public exponent size in bytes (64 bits). Verification cost also grows
     * with the exponent size, and real-world keys use small exponents (typically 65537).
     */
    private const MAX_EXPONENT_BYTES = 8;

    /**
     * @param value-of<self::ALGORITHMS> $alg
     * @param string                     $n   modulus as minimal big-endian bytes (no leading zeros)
     * @param string                     $e   public exponent as minimal big-endian bytes (no leading zeros)
     */
    private function __construct(
        int $alg,
        public readonly string $n,
        public readonly string $e,
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

        if (strlen($modulus) > self::MAX_MODULUS_BYTES) {
            throw new CoseKeyException('RSA modulus must be at most 8192 bits');
        }

        // A public exponent of 1 makes verification the identity function, so the
        // PKCS#1 encoded message can be presented as the signature and "verifies"
        // without the private key. Even exponents are likewise invalid for RSA.
        $exponent = ltrim($e, "\x00");

        if ($exponent === '' || $exponent === "\x01" || (ord(substr($exponent, -1)) & 1) === 0) {
            throw new CoseKeyException('RSA public exponent must be an odd integer greater than 1');
        }

        if (strlen($exponent) > self::MAX_EXPONENT_BYTES) {
            throw new CoseKeyException('RSA public exponent must be at most 64 bits');
        }

        // Store the trimmed values so the size ceilings bound what is persisted: leading
        // zero bytes must not smuggle an arbitrarily large bytestring past the checks.
        return new self($alg, $modulus, $exponent);
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

    public function verify(
        string $message,
        string $signature,
    ): bool
    {
        // RS256 is the only supported RSA algorithm
        return self::verifyWithOpenSsl($this->toDerSubjectPublicKeyInfo(), OPENSSL_ALGO_SHA256, $message, $signature);
    }

    /**
     * Encodes this key as a DER SubjectPublicKeyInfo (RFC 3279 §2.3.1): an RSAPublicKey under
     * rsaEncryption with NULL parameters.
     */
    private function toDerSubjectPublicKeyInfo(): string
    {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 8017 App. A.1.1).
        $rsaPublicKey = DerEncoder::encodeSequence(
            DerEncoder::encodeUnsignedInt($this->n),
            DerEncoder::encodeUnsignedInt($this->e),
        );

        return DerEncoder::encodeSequence(
            DerEncoder::encodeSequence(
                DerEncoder::encodeObjectIdentifier(self::OID_RSA_ENCRYPTION),
                DerEncoder::encodeNull(),
            ),
            DerEncoder::encodeBitString($rsaPublicKey),
        );
    }

}
