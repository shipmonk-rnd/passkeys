<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use function bin2hex;
use function in_array;
use function openssl_pkey_new;
use function strcmp;
use function strlen;
use function strrev;

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
    public const int LABEL_CRV = -1;

    /**
     * OKP key label: public key (x).
     */
    public const int LABEL_X = -2;

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
     * Field primes as big-endian hex, padded to the encoded key length. RFC 8032 §5.1.3 / §5.2.3
     * require y < p after clearing the x sign bit. For Ed448 this also rejects the seven unused
     * bits in the last octet: any nonzero value there makes y >= p.
     */
    private const array FIELD_PRIMES = [
        self::CRV_ED25519 => '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed',
        self::CRV_ED448 => '00fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    ];

    /**
     * Complete small-order y encodings (little-endian hex), with the x sign bit cleared.
     * Both signs must be rejected. This also rejects the invalid "negative zero" x encodings
     * at y = 1 and y = p - 1. Noncanonical aliases (including p and p + 1) fail the range check.
     *
     * Ed25519: libsodium's ge25519_has_small_order, orders 4, 1, 8, 8, 2 respectively.
     * Ed448: Bouncy Castle's checkPointFullVar rejects y = 0, 1, p - 1 (orders 4, 1, 2).
     * These are encoding and small-order checks, NOT full on-curve or subgroup validation.
     *
     * @see https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1022-L1075
     * @see https://github.com/bcgit/bc-java/blob/r1rv80/core/src/main/java/org/bouncycastle/math/ec/rfc8032/Ed448.java#L179-L212
     */
    private const array SMALL_ORDER_Y = [
        self::CRV_ED25519 => [
            '0000000000000000000000000000000000000000000000000000000000000000',
            '0100000000000000000000000000000000000000000000000000000000000000',
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        ],
        self::CRV_ED448 => [
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            '010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            'fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00',
        ],
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

        $y = $x;
        $y[$keyLength - 1] = $y[$keyLength - 1] & "\x7f";

        if (strcmp(bin2hex(strrev($y)), self::FIELD_PRIMES[$crv]) >= 0) {
            throw new CoseKeyException("OKP curve {$crv} has noncanonical public key encoding");
        }

        if (in_array(bin2hex($y), self::SMALL_ORDER_Y[$crv], true)) {
            throw new CoseKeyException("OKP curve {$crv} has small-order public key");
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

    protected function getOpenSslAlgorithm(): int
    {
        // EdDSA is a pure signature scheme; OpenSSL takes no separate message digest.
        return 0;
    }

}
