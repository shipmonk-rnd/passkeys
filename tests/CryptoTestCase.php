<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use OpenSSLAsymmetricKey;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseEc2Key;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Cose\CoseRsaKey;

use function array_key_exists;
use function base64_decode;
use function implode;
use function is_array;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function preg_replace;
use function str_pad;

use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const STR_PAD_LEFT;

/**
 * Base class for tests that need real OpenSSL key material paired with the
 * equivalent parsed {@see CoseKey}.
 */
abstract class CryptoTestCase extends WebAuthnTestCase
{
	/**
	 * Generates a fresh key pair for the given COSE algorithm and returns both the
	 * parsed COSE public key and the OpenSSL private key (for signing in tests).
	 *
	 * @return array{CoseKey, OpenSSLAsymmetricKey}
	 */
	protected static function generateCoseKeyPair(int $alg): array
	{
		if ($alg === CoseAlgorithmIdentifier::RS256) {
			$privateKey = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
			$details = self::keyDetails($privateKey);

			$coseKey = CoseKey::fromCborMap(self::cborMap([
				1 => CoseRsaKey::KTY,
				3 => $alg,
				-1 => self::stringField($details, 'rsa', 'n'),
				-2 => self::stringField($details, 'rsa', 'e'),
			]));

			return [$coseKey, $privateKey];
		}

		[$curveName, $crv, $coordinateLength] = self::ec2Spec($alg);

		$privateKey = self::generateKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);
		$details = self::keyDetails($privateKey);

		$coseKey = CoseKey::fromCborMap(self::cborMap([
			1 => CoseEc2Key::KTY,
			3 => $alg,
			-1 => $crv,
			-2 => str_pad(self::stringField($details, 'ec', 'x'), $coordinateLength, "\x00", STR_PAD_LEFT),
			-3 => str_pad(self::stringField($details, 'ec', 'y'), $coordinateLength, "\x00", STR_PAD_LEFT),
		]));

		return [$coseKey, $privateKey];
	}

	/**
	 * @return array{string, int, int} OpenSSL curve name, COSE curve id, coordinate length
	 */
	protected static function ec2Spec(int $alg): array
	{
		return match ($alg) {
			CoseAlgorithmIdentifier::ES256 => ['prime256v1', CoseEc2Key::CRV_P256, 32],
			CoseAlgorithmIdentifier::ES384 => ['secp384r1', CoseEc2Key::CRV_P384, 48],
			CoseAlgorithmIdentifier::ES512 => ['secp521r1', CoseEc2Key::CRV_P521, 66],
			default => self::fail("Unsupported test algorithm {$alg}"),
		};
	}

	/**
	 * @param  array<string, int|string> $config
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
	 * @param  array<array-key, mixed> $data
	 */
	protected static function stringField(array $data, string ...$path): string
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
