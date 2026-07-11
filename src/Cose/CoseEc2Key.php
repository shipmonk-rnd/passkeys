<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use function openssl_pkey_new;
use function strlen;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

/**
 * COSE key of type EC2 (two-coordinate elliptic curve), e.g. ES256.
 *
 * @extends CoseKey<key-of<self::ALGORITHMS>>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1 EC2 key parameters
 * @api
 */
final readonly class CoseEc2Key extends CoseKey
{

    /**
     * Key type value for EC2 keys.
     */
    public const int KTY = 2;

    /**
     * COSE curve identifier: NIST P-256.
     */
    public const int CRV_P256 = 1;

    /**
     * COSE curve identifier: NIST P-384.
     */
    public const int CRV_P384 = 2;

    /**
     * COSE curve identifier: NIST P-521.
     */
    public const int CRV_P521 = 3;

    /**
     * EC2 key label: curve (crv).
     */
    private const int LABEL_CRV = -1;

    /**
     * EC2 key label: x-coordinate.
     */
    private const int LABEL_X = -2;

    /**
     * EC2 key label: y-coordinate.
     */
    private const int LABEL_Y = -3;

    /**
     * Maps each supported algorithm to its mandated curve, coordinate length in bytes,
     * OpenSSL curve name, and OpenSSL message-digest algorithm.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1 ECDSA
     */
    private const array ALGORITHMS = [
        CoseAlgorithmIdentifier::ES256 => [self::CRV_P256, 32, 'prime256v1', OPENSSL_ALGO_SHA256],
        CoseAlgorithmIdentifier::ES384 => [self::CRV_P384, 48, 'secp384r1', OPENSSL_ALGO_SHA384],
        CoseAlgorithmIdentifier::ES512 => [self::CRV_P521, 66, 'secp521r1', OPENSSL_ALGO_SHA512],
    ];

    /**
     * @param key-of<self::ALGORITHMS> $alg
     * @param self::CRV_*              $crv
     * @param string                   $x   raw x-coordinate bytes (fixed length for the curve)
     * @param string                   $y   raw y-coordinate bytes (fixed length for the curve)
     */
    private function __construct(
        int $alg,
        public int $crv,
        public string $x,
        public string $y,
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
        $crv = $map->getInt(self::LABEL_CRV);
        $x = $map->getString(self::LABEL_X);
        $y = $map->getString(self::LABEL_Y);

        if (!isset(self::ALGORITHMS[$alg])) {
            throw new CoseKeyException("Unsupported EC2 algorithm {$alg}");
        }

        [$expectedCrv, $coordinateLength] = self::ALGORITHMS[$alg];

        if ($crv !== $expectedCrv) {
            throw new CoseKeyException("EC2 algorithm {$alg} requires curve {$expectedCrv}, got {$crv}");
        }

        if (strlen($x) !== $coordinateLength || strlen($y) !== $coordinateLength) {
            throw new CoseKeyException("EC2 curve {$crv} requires {$coordinateLength}-byte coordinates");
        }

        return new self($alg, $crv, $x, $y);
    }

    public function toBytes(): string
    {
        return CborEncoder::encodeMap([
            [CborEncoder::encodeInt(self::LABEL_KTY), CborEncoder::encodeInt(self::KTY)],
            [CborEncoder::encodeInt(self::LABEL_ALG), CborEncoder::encodeInt($this->alg)],
            [CborEncoder::encodeInt(self::LABEL_CRV), CborEncoder::encodeInt($this->crv)],
            [CborEncoder::encodeInt(self::LABEL_X), CborEncoder::encodeByteString($this->x)],
            [CborEncoder::encodeInt(self::LABEL_Y), CborEncoder::encodeByteString($this->y)],
        ]);
    }

    protected function toOpenSslPublicKey(): OpenSSLAsymmetricKey|false
    {
        return openssl_pkey_new([
            'ec' => [
                'curve_name' => self::ALGORITHMS[$this->alg][2],
                'x' => $this->x,
                'y' => $this->y,
            ],
        ]);
    }

    protected function opensslAlgorithm(): int
    {
        return self::ALGORITHMS[$this->alg][3];
    }

}
