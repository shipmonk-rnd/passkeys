<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Cbor\CborEncoder;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Der\DerEncoder;

use function in_array;
use function strlen;

/**
 * COSE key of type OKP (Octet Key Pair), i.e. an Edwards-curve key such as Ed25519.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2 EdDSA
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.2 OKP key parameters
 * @api
 */
final class CoseOkpKey extends CoseKey
{
	/** Key type value for OKP keys. */
	public const int KTY = 1;

	/** COSE curve identifier: Ed25519. */
	public const int CRV_ED25519 = 6;

	/** COSE curve identifier: Ed448. */
	public const int CRV_ED448 = 7;

	/** OKP key label: curve (crv). */
	private const int LABEL_CRV = -1;

	/** OKP key label: public key (x). */
	private const int LABEL_X = -2;

	/**
	 * Maps each supported algorithm to the curves it allows: the generic EdDSA identifier
	 * spans both Edwards curves, while the fully-specified RFC 9864 identifiers pin one.
	 */
	private const array ALGORITHMS = [
		CoseAlgorithmIdentifier::EdDSA => [self::CRV_ED25519, self::CRV_ED448],
		CoseAlgorithmIdentifier::Ed25519 => [self::CRV_ED25519],
		CoseAlgorithmIdentifier::Ed448 => [self::CRV_ED448],
	];

	/**
	 * Maps each supported curve to its public-key length in bytes and its id-Ed* OID
	 * (RFC 8410 §3); note these OIDs carry no algorithm parameters.
	 */
	private const array CURVES = [
		self::CRV_ED25519 => [32, '1.3.101.112'],
		self::CRV_ED448 => [57, '1.3.101.113'],
	];

	/**
	 * @param string $x raw public key bytes (fixed length for the curve)
	 */
	private function __construct(
		int $alg,
		public readonly int $crv,
		public readonly string $x,
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
		$crv = $map->getInt(self::LABEL_CRV);
		$x = $map->getString(self::LABEL_X);

		if (!isset(self::ALGORITHMS[$alg])) {
			throw new CoseKeyException("Unsupported OKP algorithm {$alg}");
		}

		if (!in_array($crv, self::ALGORITHMS[$alg], true)) {
			throw new CoseKeyException("OKP algorithm {$alg} does not allow curve {$crv}");
		}

		[$keyLength] = self::CURVES[$crv];

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

	public function toDerSubjectPublicKeyInfo(): string
	{
		return DerEncoder::encodeSequence(
			DerEncoder::encodeSequence(DerEncoder::encodeObjectIdentifier(self::CURVES[$this->crv][1])),
			DerEncoder::encodeBitString($this->x),
		);
	}
}
