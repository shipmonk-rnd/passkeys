<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Cose;

use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Binary\BytesReaderException;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use ShipMonk\Passkeys\Cbor\InvalidCborException;
use function base64_encode;
use function chunk_split;
use function implode;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;

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
     * Verifies a signature over $message against this public key.
     *
     * For ECDSA algorithms the signature is expected in the ASN.1 DER form
     * (Ecdsa-Sig-Value) produced by authenticators; for RSASSA-PKCS1-v1_5 it is the
     * raw signature; for EdDSA it is the raw Ed25519 (64-byte) signature.
     *
     * @see https://www.rfc-editor.org/rfc/rfc9053.html signature algorithms
     * @throws CoseKeyLoadException if the key material cannot be loaded
     */
    abstract public function verify(
        string $message,
        string $signature,
    ): bool;

    /**
     * Verifies a signature with ext-openssl against a public key given as a DER-encoded
     * SubjectPublicKeyInfo (RFC 5280 §4.1.2.7), the one public-key form that
     * {@see \openssl_pkey_get_public()} loads on every supported PHP version.
     *
     * @param int $algorithm the OpenSSL message-digest algorithm (an OPENSSL_ALGO_* constant)
     *
     * @throws CoseKeyLoadException if OpenSSL rejects the key material
     *
     * @internal an implementation detail of the PHP 8.1 support, not covered by the backward-compatibility promise
     */
    final protected static function verifyWithOpenSsl(
        string $subjectPublicKeyInfo,
        int $algorithm,
        string $message,
        string $signature,
    ): bool
    {
        self::clearOpenSslErrors(); // Discard any stale entries so a failure below reports only this call's errors.

        $publicKey = openssl_pkey_get_public(self::toPem($subjectPublicKeyInfo));

        if ($publicKey === false) {
            throw new CoseKeyLoadException('Failed to load public key: ' . self::getOpenSslErrors());
        }

        $result = openssl_verify($message, $signature, $publicKey, $algorithm);

        // 1 = verified; 0 = signature does not match; -1 = malformed signature or an
        // OpenSSL error. A caller cannot tell attacker-supplied garbage apart from a
        // genuine mismatch, so anything but 1 is a verification failure, not an exception.
        return $result === 1;
    }

    private static function toPem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function getOpenSslErrors(): string
    {
        $errors = [];

        while (($error = openssl_error_string()) !== false) {
            $errors[] = $error;
        }

        return implode('; ', $errors);
    }

    private static function clearOpenSslErrors(): void
    {
        self::getOpenSslErrors();
    }

}
