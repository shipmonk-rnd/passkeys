<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Binary\BytesReaderException;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use ShipMonk\Passkeys\Cbor\InvalidCborException;
use function implode;
use function openssl_error_string;
use function openssl_verify;
use function sodium_crypto_sign_verify_detached;
use function strlen;
use const SODIUM_CRYPTO_SIGN_BYTES;

/**
 * A COSE_Key as used by WebAuthn credential public keys.
 *
 * @template-covariant TAlg of CoseAlgorithmIdentifier::* = CoseAlgorithmIdentifier::* the COSE algorithm identifiers the key type supports
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7 COSE key structure
 * @see https://www.rfc-editor.org/rfc/rfc9053.html key type / algorithm parameters
 * @api
 */
abstract class CoseKey
{

    /**
     * Common COSE key label: key type (kty).
     */
    public const LABEL_KTY = 1;

    /**
     * Common COSE key label: algorithm (alg).
     */
    public const LABEL_ALG = 3;

    /**
     * @param TAlg $alg
     */
    protected function __construct(
        public readonly int $alg,
    )
    {
    }

    /**
     * @throws CborMapException
     * @throws CoseKeyException
     */
    public static function fromCborMap(CborMap $map): CoseKey
    {
        $kty = $map->getInt(self::LABEL_KTY);

        return match ($kty) {
            CoseOkpKey::KTY => CoseOkpKey::fromCborMap($map),
            CoseEc2Key::KTY => CoseEc2Key::fromCborMap($map),
            CoseRsaKey::KTY => CoseRsaKey::fromCborMap($map),
            default => throw new CoseKeyException("Unsupported COSE key type {$kty}"),
        };
    }

    /**
     * Reconstructs a key previously produced by {@see self::toBytes()} — for loading a stored
     * credential's public key. The inverse of {@see self::toBytes()}.
     *
     * @throws CoseKeyException on malformed input (not a single, complete COSE_Key CBOR map)
     */
    public static function fromBytes(string $bytes): CoseKey
    {
        try {
            $map = BytesReader::read($bytes, CborMap::fromBytesReader(...));
            return self::fromCborMap($map);

        } catch (BytesReaderException | CborMapException | InvalidCborException $e) {
            throw new CoseKeyException('Malformed COSE key', previous: $e);
        }
    }

    /**
     * Serialises this key as a COSE_Key CBOR map — a stable, self-contained byte string suitable
     * for persisting a credential's public key (e.g. one blob column per credential). Reconstruct
     * it with {@see self::fromBytes()}.
     */
    abstract public function toBytes(): string;

    /**
     * Verifies a signature over $message against this public key using ext-openssl, or
     * ext-sodium for EdDSA.
     *
     * For ECDSA algorithms the signature is expected in the ASN.1 DER form
     * (Ecdsa-Sig-Value) produced by authenticators; for RSASSA-PKCS1-v1_5 it is the
     * raw signature; for EdDSA it is the raw Ed25519 (64-byte) signature. The first two
     * are what {@see \openssl_verify()} consumes directly, the last one is what
     * {@see \sodium_crypto_sign_verify_detached()} consumes.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053.html signature algorithms
     * @throws CoseKeyLoadException if OpenSSL rejects the key material
     */
    final public function verify(
        string $message,
        string $signature,
    ): bool
    {
        $this->clearOpenSslErrors(); // Discard any stale entries so a failure below reports only this call's errors.

        $publicKey = $this->toOpenSslPublicKey();

        if ($publicKey === false) {
            throw new CoseKeyLoadException('Failed to load public key: ' . $this->getOpenSslErrors());
        }

        $algorithm = $this->getOpenSslAlgorithm();

        // Before PHP 8.4, ext-openssl can load an EdDSA key but cannot verify with it, so libsodium
        // verifies OKP keys (Ed25519 is the only supported curve) against the raw public key. It
        // throws on a signature of the wrong length; like any other malformed signature, that is a
        // verification failure, not an exception.
        if ($this instanceof CoseOkpKey) {
            return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                && sodium_crypto_sign_verify_detached($signature, $message, $this->x);
        }

        $result = openssl_verify($message, $signature, $publicKey, $algorithm);

        // 1 = verified; 0 = signature does not match; -1 = malformed signature or an
        // OpenSSL error. A caller cannot tell attacker-supplied garbage apart from a
        // genuine mismatch, so anything but 1 is a verification failure, not an exception.
        return $result === 1;
    }

    /**
     * Builds an ext-openssl public key handle for this key by loading its DER-encoded
     * SubjectPublicKeyInfo via {@see \openssl_pkey_get_public()}, the form consumed by
     * {@see \openssl_verify()} in {@see self::verify()}. Returns false if OpenSSL rejects the key
     * material.
     */
    abstract protected function toOpenSslPublicKey(): OpenSSLAsymmetricKey|false;

    /**
     * The OpenSSL message-digest algorithm to verify with — an OPENSSL_ALGO_* constant,
     * or 0 for pure signature schemes (EdDSA), which take no separate digest.
     */
    abstract protected function getOpenSslAlgorithm(): int;

    private function getOpenSslErrors(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return implode('; ', $errors);
    }

    private function clearOpenSslErrors(): void
    {
        self::getOpenSslErrors();
    }

}
