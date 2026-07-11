<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use function openssl_pkey_new;
use function strlen;

/**
 * COSE key of type OKP (Octet Key Pair), i.e. an Edwards-curve key such as Ed25519.
 *
 * @extends CoseKey<key-of<self::ALGORITHMS>>
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2 EdDSA
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.2 OKP key parameters
 * @api
 */
final readonly class CoseOkpKey extends CoseKey
{

    /**
     * Key type value for OKP keys.
     */
    public const int KTY = 1;

    /**
     * COSE curve identifier: Ed25519.
     */
    public const int CRV_ED25519 = 6;

    /**
     * COSE curve identifier: Ed448.
     */
    public const int CRV_ED448 = 7;

    /**
     * OKP key label: curve (crv).
     */
    private const int LABEL_CRV = -1;

    /**
     * OKP key label: public key (x).
     */
    private const int LABEL_X = -2;

    /**
     * Maps each supported algorithm to its mandated curve, public-key length in bytes,
     * and OpenSSL key-type name.
     *
     * WebAuthn §5.8.5 requires keys with the generic EdDSA identifier to use Ed25519, so
     * despite being polymorphic in plain COSE it pins a single curve here; Ed448 keys must
     * use the fully-specified RFC 9864 identifier.
     */
    private const array ALGORITHMS = [
        CoseAlgorithmIdentifier::EdDSA => [self::CRV_ED25519, 32, 'ed25519'],
        CoseAlgorithmIdentifier::Ed448 => [self::CRV_ED448, 57, 'ed448'],
    ];

    /**
     * @param key-of<self::ALGORITHMS> $alg
     * @param self::CRV_*              $crv
     * @param string                   $x   raw public key bytes (fixed length for the curve)
     */
    private function __construct(
        int $alg,
        public int $crv,
        public string $x,
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

        if (!isset(self::ALGORITHMS[$alg])) {
            throw new CoseKeyException("Unsupported OKP algorithm {$alg}");
        }

        [$expectedCrv, $keyLength] = self::ALGORITHMS[$alg];

        if ($crv !== $expectedCrv) {
            throw new CoseKeyException("OKP algorithm {$alg} requires curve {$expectedCrv}, got {$crv}");
        }

        if (strlen($x) !== $keyLength) {
            throw new CoseKeyException("OKP curve {$crv} requires {$keyLength}-byte public key");
        }

        return new self($alg, $crv, $x);
    }

    public function toBytes(): string
    {
        return CborEncoder::encodeMap([
            [CborEncoder::encodeInt(self::LABEL_KTY), CborEncoder::encodeInt(self::KTY)],
            [CborEncoder::encodeInt(self::LABEL_ALG), CborEncoder::encodeInt($this->alg)],
            [CborEncoder::encodeInt(self::LABEL_CRV), CborEncoder::encodeInt($this->crv)],
            [CborEncoder::encodeInt(self::LABEL_X), CborEncoder::encodeByteString($this->x)],
        ]);
    }

    protected function toOpenSslPublicKey(): OpenSSLAsymmetricKey|false
    {
        return openssl_pkey_new([
            self::ALGORITHMS[$this->alg][2] => [
                'pub_key' => $this->x,
            ],
        ]);
    }

    protected function opensslAlgorithm(): int
    {
        // EdDSA is a pure signature scheme; OpenSSL takes no separate message digest.
        return 0;
    }

}
