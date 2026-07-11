<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests;

use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Cose\CoseKey;
use ShipMonk\Passkeys\Cose\CoseOkpKey;
use ShipMonk\Passkeys\Cose\CoseRsaKey;
use function array_key_exists;
use function base64_decode;
use function implode;
use function is_array;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use function preg_replace;
use function str_pad;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_RSA;
use const STR_PAD_LEFT;

/**
 * Base class for tests that need real OpenSSL key material paired with the
 * equivalent parsed {@see CoseKey}.
 */
abstract class CryptoTestCase extends PasskeysTestCase
{

    /**
     * Generates a fresh key pair for the given COSE algorithm and returns both the
     * parsed COSE public key and the OpenSSL private key (for signing in tests).
     *
     * @param CoseAlgorithmIdentifier::* $alg
     * @return array{CoseKey, OpenSSLAsymmetricKey}
     */
    protected static function generateCoseKeyPair(int $alg): array
    {
        [$privateKey, $entries] = self::generateKeyAndCoseEntries($alg);

        return [CoseKey::fromCborMap(self::cborMap($entries)), $privateKey];
    }

    /**
     * Generates a fresh key pair and returns the OpenSSL private key together with the
     * integer-keyed COSE map entries describing its public key — the same shape an
     * authenticator embeds in attested credential data.
     *
     * @param CoseAlgorithmIdentifier::* $alg
     * @return array{OpenSSLAsymmetricKey, array<int, int|string>}
     */
    protected static function generateKeyAndCoseEntries(int $alg): array
    {
        if ($alg === CoseAlgorithmIdentifier::RS256) {
            $privateKey = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
            $details = self::keyDetails($privateKey);

            return [$privateKey, [
                1 => CoseRsaKey::KTY,
                3 => $alg,
                -1 => self::stringField($details, 'rsa', 'n'),
                -2 => self::stringField($details, 'rsa', 'e'),
            ]];
        }

        $crv = match ($alg) {
            // WebAuthn §5.8.5 pins the generic EdDSA identifier to Ed25519
            CoseAlgorithmIdentifier::EdDSA => CoseOkpKey::CRV_ED25519,
            CoseAlgorithmIdentifier::Ed448 => CoseOkpKey::CRV_ED448,
            default => null,
        };

        if ($crv !== null) {
            [$keyType, $detailsField] = match ($crv) {
                CoseOkpKey::CRV_ED25519 => [OPENSSL_KEYTYPE_ED25519, 'ed25519'],
                CoseOkpKey::CRV_ED448 => [OPENSSL_KEYTYPE_ED448, 'ed448'],
            };

            $privateKey = self::generateKey(['private_key_type' => $keyType]);
            $details = self::keyDetails($privateKey);

            return [$privateKey, [
                1 => CoseOkpKey::KTY,
                3 => $alg,
                -1 => $crv,
                -2 => self::stringField($details, $detailsField, 'pub_key'),
            ]];
        }

        [$curveName, $crv, $coordinateLength] = self::ec2Spec($alg);

        $privateKey = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);
        $details = self::keyDetails($privateKey);

        return [$privateKey, [
            1 => CoseEc2Key::KTY,
            3 => $alg,
            -1 => $crv,
            -2 => str_pad(self::stringField($details, 'ec', 'x'), $coordinateLength, "\x00", STR_PAD_LEFT),
            -3 => str_pad(self::stringField($details, 'ec', 'y'), $coordinateLength, "\x00", STR_PAD_LEFT),
        ]];
    }

    /**
     * Signs a message with the OpenSSL private key using the digest the given COSE algorithm
     * mandates, producing exactly the signature encoding {@see \ShipMonk\Passkeys\Cose\CoseKey::verify()}
     * expects (ASN.1 DER for ECDSA, raw PKCS#1 for RSA, raw 64-byte for Ed25519).
     *
     * @param CoseAlgorithmIdentifier::* $alg
     */
    protected static function sign(
        OpenSSLAsymmetricKey $privateKey,
        string $message,
        int $alg,
    ): string
    {
        if (!openssl_sign($message, $signature, $privateKey, self::opensslDigest($alg)) || !is_string($signature)) {
            self::fail('Failed to sign: ' . openssl_error_string());
        }

        return $signature;
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    protected static function opensslDigest(int $alg): int
    {
        return match ($alg) {
            CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256 => OPENSSL_ALGO_SHA256,
            CoseAlgorithmIdentifier::ES384 => OPENSSL_ALGO_SHA384,
            CoseAlgorithmIdentifier::ES512 => OPENSSL_ALGO_SHA512,
            // EdDSA is a pure signature scheme (no prehash)
            CoseAlgorithmIdentifier::EdDSA, CoseAlgorithmIdentifier::Ed448 => 0,
        };
    }

    /**
     * @param CoseAlgorithmIdentifier::ES256|CoseAlgorithmIdentifier::ES384|CoseAlgorithmIdentifier::ES512 $alg
     * @return array{string, int, int} OpenSSL curve name, COSE curve id, coordinate length
     */
    protected static function ec2Spec(int $alg): array
    {
        return match ($alg) {
            CoseAlgorithmIdentifier::ES256 => ['prime256v1', CoseEc2Key::CRV_P256, 32],
            CoseAlgorithmIdentifier::ES384 => ['secp384r1', CoseEc2Key::CRV_P384, 48],
            CoseAlgorithmIdentifier::ES512 => ['secp521r1', CoseEc2Key::CRV_P521, 66],
        };
    }

    /**
     * @param array<string, int|string> $config
     */
    protected static function generateKey(array $config): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($config);

        if ($key === false) {
            self::fail('Failed to generate key: ' . openssl_error_string());
        }

        return $key;
    }

    /**
     * @return array<array-key, mixed>
     */
    protected static function keyDetails(OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            self::fail('Failed to read key details: ' . openssl_error_string());
        }

        return $details;
    }

    /**
     * @param array<array-key, mixed> $data
     */
    protected static function stringField(
        array $data,
        string ...$path,
    ): string
    {
        $value = $data;

        foreach ($path as $key) {
            if (!is_array($value) || !array_key_exists($key, $value)) {
                self::fail('Missing field ' . implode('.', $path));
            }

            $value = $value[$key];
        }

        if (!is_string($value)) {
            self::fail('Field ' . implode('.', $path) . ' is not a string');
        }

        return $value;
    }

    protected static function pemToDer(string $pem): string
    {
        $base64 = preg_replace('~-----(?:BEGIN|END)[^-]+-----|\s+~', '', $pem) ?? '';
        $der = base64_decode($base64, strict: true);

        if ($der === false) {
            self::fail('Failed to decode PEM');
        }

        return $der;
    }

}
