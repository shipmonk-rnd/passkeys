<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Cbor\CborEncoder;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Der\DerEncoder;

use function in_array;
use function ltrim;
use function ord;
use function strlen;
use function substr;

use const OPENSSL_ALGO_SHA256;

/**
 * COSE key of type RSA, e.g. RS256.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8230.html#section-4 RSA key parameters
 * @api
 */
final class CoseRsaKey extends CoseKey
{
	/** Key type value for RSA keys. */
	public const int KTY = 3;

	/** RSA key label: modulus (n). */
	private const int LABEL_N = -1;

	/** RSA key label: public exponent (e). */
	private const int LABEL_E = -2;

	/** OID for rsaEncryption (RFC 8017 App. C / RFC 3279 §2.3.1). */
	private const string OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

	/** Algorithms that use an RSA key. */
	private const array ALGORITHMS = [
		CoseAlgorithmIdentifier::RS256,
	];

	/** Minimum accepted modulus size in bytes (2048 bits; RFC 8230 §6.1). */
	private const int MIN_MODULUS_BYTES = 256;

	/**
	 * @param string $n modulus as raw big-endian bytes
	 * @param string $e public exponent as raw big-endian bytes
	 */
	private function __construct(
		int $alg,
		public readonly string $n,
		public readonly string $e,
	) {
		parent::__construct($alg);
	}

	/**
	 * @throws CoseKeyException
	 * @throws CborMapException
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

		// A public exponent of 1 makes verification the identity function, so the
		// PKCS#1 encoded message can be presented as the signature and "verifies"
		// without the private key. Even exponents are likewise invalid for RSA.
		$exponent = ltrim($e, "\x00");

		if ($exponent === '' || $exponent === "\x01" || (ord(substr($exponent, -1)) & 1) === 0) {
			throw new CoseKeyException('RSA public exponent must be an odd integer greater than 1');
		}

		return new self($alg, $n, $e);
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

	public function toDerSubjectPublicKeyInfo(): string
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

	protected function opensslAlgorithm(): int
	{
		return OPENSSL_ALGO_SHA256; // RS256 is the only supported RSA algorithm
	}
}
