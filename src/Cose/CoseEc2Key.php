<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Cbor\CborEncoder;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Der\DerEncoder;

use function strlen;

/**
 * COSE key of type EC2 (two-coordinate elliptic curve), e.g. ES256.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1 EC2 key parameters
 * @api
 */
final class CoseEc2Key extends CoseKey
{
	/** Key type value for EC2 keys. */
	public const KTY = 2;

	/** COSE curve identifier: NIST P-256. */
	public const CRV_P256 = 1;

	/** COSE curve identifier: NIST P-384. */
	public const CRV_P384 = 2;

	/** COSE curve identifier: NIST P-521. */
	public const CRV_P521 = 3;

	/** EC2 key label: curve (crv). */
	private const LABEL_CRV = -1;

	/** EC2 key label: x-coordinate. */
	private const LABEL_X = -2;

	/** EC2 key label: y-coordinate. */
	private const LABEL_Y = -3;

	/** OID for id-ecPublicKey (RFC 5480 §2.1.1). */
	private const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';

	/**
	 * Maps each supported algorithm to its mandated curve and coordinate length in bytes.
	 *
	 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1 ECDSA
	 */
	private const ALGORITHMS = [
		CoseAlgorithmIdentifier::ES256 => [self::CRV_P256, 32, '1.2.840.10045.3.1.7'],
		CoseAlgorithmIdentifier::ES384 => [self::CRV_P384, 48, '1.3.132.0.34'],
		CoseAlgorithmIdentifier::ES512 => [self::CRV_P521, 66, '1.3.132.0.35'],
	];

	/**
	 * @param string $x raw x-coordinate bytes (fixed length for the curve)
	 * @param string $y raw y-coordinate bytes (fixed length for the curve)
	 */
	private function __construct(
		int $alg,
		public int $crv,
		public string $x,
		public string $y,
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
		$y = $map->getString(self::LABEL_Y);

		if (!isset(self::ALGORITHMS[$alg])) {
			throw new CoseKeyException("Unsupported EC2 algorithm {$alg}");
		}

		[$expectedCrv, $coordinateLength] = self::ALGORITHMS[$alg];

		if ($crv !== $expectedCrv) {
			throw new CoseKeyException("EC2 algorithm {$alg} requires curve {$expectedCrv}, got {$crv}");
		}

		if (strlen($x) !== $coordinateLength || strlen($y) !== $coordinateLength) {
			throw new CoseKeyException("EC2 curve {$crv} requires {$coordinateLength}-byte coordinates");
		}

		return new self($alg, $crv, $x, $y);
	}

	public function toBytes(): string
	{
		return CborEncoder::encodeMap([
			[CborEncoder::encodeInt(self::LABEL_KTY), CborEncoder::encodeInt(self::KTY)],
			[CborEncoder::encodeInt(self::LABEL_ALG), CborEncoder::encodeInt($this->alg)],
			[CborEncoder::encodeInt(self::LABEL_CRV), CborEncoder::encodeInt($this->crv)],
			[CborEncoder::encodeInt(self::LABEL_X), CborEncoder::encodeByteString($this->x)],
			[CborEncoder::encodeInt(self::LABEL_Y), CborEncoder::encodeByteString($this->y)],
		]);
	}

	public function toDerSubjectPublicKeyInfo(): string
	{
		$curveOid = self::ALGORITHMS[$this->alg][2];

		// Uncompressed point: 0x04 || X || Y (RFC 5480 §2.2).
		$point = "\x04" . $this->x . $this->y;

		$spki = DerEncoder::encodeSequence(
			DerEncoder::encodeSequence(
				DerEncoder::encodeObjectIdentifier(self::OID_EC_PUBLIC_KEY)
				. DerEncoder::encodeObjectIdentifier($curveOid),
			)
			. DerEncoder::encodeBitString($point),
		);

		return $spki;
	}
}
