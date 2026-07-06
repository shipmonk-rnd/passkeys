<?php declare(strict_types = 1);

namespace WebAuthnX\Crypto;

use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseKey;

use function base64_encode;
use function chunk_split;
use function implode;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;

/**
 * Verifies a signature over some bytes against a COSE public key using ext-openssl.
 *
 * For ECDSA algorithms the signature is expected in the ASN.1 DER form
 * (Ecdsa-Sig-Value) produced by authenticators; for RSASSA-PKCS1-v1_5 it is the
 * raw signature; for EdDSA it is the raw Ed25519 (64-byte) or Ed448 (114-byte)
 * signature. All are what
 * {@see \openssl_verify()} consumes directly (EdDSA requires OpenSSL 3.0 / PHP 8.4).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html signature algorithms
 * @api
 */
final class SignatureVerifier
{
	/** EdDSA is a pure signature scheme; OpenSSL takes no separate message digest. */
	private const int OPENSSL_ALGO_EDDSA = 0;

	/** Maps each supported COSE algorithm to its OpenSSL message-digest algorithm. */
	private const array OPENSSL_ALGORITHMS = [
		CoseAlgorithmIdentifier::ES256 => OPENSSL_ALGO_SHA256,
		CoseAlgorithmIdentifier::ES384 => OPENSSL_ALGO_SHA384,
		CoseAlgorithmIdentifier::ES512 => OPENSSL_ALGO_SHA512,
		CoseAlgorithmIdentifier::RS256 => OPENSSL_ALGO_SHA256,
		CoseAlgorithmIdentifier::EdDSA => self::OPENSSL_ALGO_EDDSA,
		CoseAlgorithmIdentifier::Ed25519 => self::OPENSSL_ALGO_EDDSA,
		CoseAlgorithmIdentifier::Ed448 => self::OPENSSL_ALGO_EDDSA,
	];

	/**
	 * @throws SignatureVerificationException
	 */
	public function verify(CoseKey $key, string $message, string $signature): bool
	{
		if (!isset(self::OPENSSL_ALGORITHMS[$key->alg])) {
			throw new SignatureVerificationException("Unsupported algorithm {$key->alg}");
		}

		// Discard any stale entries so a failure below reports only this call's errors.
		self::clearOpensslErrors();

		$publicKey = openssl_pkey_get_public(self::toPem($key->toDerSubjectPublicKeyInfo()));

		if ($publicKey === false) {
			throw new SignatureVerificationException('Failed to load public key: ' . self::opensslErrors());
		}

		$result = openssl_verify(
			$message,
			$signature,
			$publicKey,
			self::OPENSSL_ALGORITHMS[$key->alg],
		);

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

	private static function opensslErrors(): string
	{
		$errors = [];

		while (($error = openssl_error_string()) !== false) {
			$errors[] = $error;
		}

		return implode('; ', $errors);
	}

	private static function clearOpensslErrors(): void
	{
		while (openssl_error_string() !== false) {
			// drain the queue
		}
	}
}
