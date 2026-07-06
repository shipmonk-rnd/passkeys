<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Binary\BytesReaderException;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Cbor\InvalidCborException;

use function base64_encode;
use function chunk_split;
use function implode;
use function openssl_error_string;
use function openssl_pkey_get_public;
use function openssl_verify;

/**
 * A COSE_Key as used by WebAuthn credential public keys.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7 COSE key structure
 * @see https://www.rfc-editor.org/rfc/rfc9053.html key type / algorithm parameters
 * @template-covariant TAlg of CoseAlgorithmIdentifier::* = CoseAlgorithmIdentifier::* the COSE algorithm identifiers the key type supports
 * @api
 */
abstract class CoseKey
{
	/** Common COSE key label: key type (kty). */
	protected const int LABEL_KTY = 1;

	/** Common COSE key label: algorithm (alg). */
	protected const int LABEL_ALG = 3;

	/**
	 * @param TAlg $alg
	 */
	protected function __construct(
		public readonly int $alg,
	) {
	}

	/**
	 * @throws CoseKeyException
	 * @throws CborMapException
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
			return BytesReader::read($bytes, static function (BytesReader $reader): CoseKey {
				return self::fromCborMap(CborMap::fromBytesReader($reader));
			});

		} catch (BytesReaderException | InvalidCborException | CborMapException $e) {
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
	 * Encodes this key as a DER-encoded SubjectPublicKeyInfo (RFC 5280 §4.1.2.7),
	 * the form consumed by {@see \openssl_pkey_get_public()}.
	 */
	abstract public function toDerSubjectPublicKeyInfo(): string;

	/**
	 * Verifies a signature over $message against this public key using ext-openssl.
	 *
	 * For ECDSA algorithms the signature is expected in the ASN.1 DER form
	 * (Ecdsa-Sig-Value) produced by authenticators; for RSASSA-PKCS1-v1_5 it is the
	 * raw signature; for EdDSA it is the raw Ed25519 (64-byte) or Ed448 (114-byte)
	 * signature. All are what
	 * {@see \openssl_verify()} consumes directly (EdDSA requires OpenSSL 3.0 / PHP 8.4).
	 *
	 * @see https://www.rfc-editor.org/rfc/rfc9053.html signature algorithms
	 * @throws SignatureVerificationException if OpenSSL rejects the key material
	 */
	final public function verify(string $message, string $signature): bool
	{
		// Discard any stale entries so a failure below reports only this call's errors.
		self::clearOpensslErrors();

		$publicKey = openssl_pkey_get_public(self::toPem($this->toDerSubjectPublicKeyInfo()));

		if ($publicKey === false) {
			throw new SignatureVerificationException('Failed to load public key: ' . self::opensslErrors());
		}

		$result = openssl_verify($message, $signature, $publicKey, $this->opensslAlgorithm());

		// 1 = verified; 0 = signature does not match; -1 = malformed signature or an
		// OpenSSL error. A caller cannot tell attacker-supplied garbage apart from a
		// genuine mismatch, so anything but 1 is a verification failure, not an exception.
		return $result === 1;
	}

	/**
	 * The OpenSSL message-digest algorithm to verify with — an OPENSSL_ALGO_* constant,
	 * or 0 for pure signature schemes (EdDSA), which take no separate digest.
	 */
	abstract protected function opensslAlgorithm(): int;

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
