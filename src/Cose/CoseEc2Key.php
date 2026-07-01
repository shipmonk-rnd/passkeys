<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborMap;

/**
 * COSE key of type EC2 (two-coordinate elliptic curve), e.g. ES256.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1 EC2 key parameters
 */
final class CoseEc2Key extends CoseKey
{
	/** Key type value for EC2 keys. */
	public const KTY = 2;

	/** EC2 key label: curve (crv). */
	private const LABEL_CRV = -1;

	/** EC2 key label: x-coordinate. */
	private const LABEL_X = -2;

	/** EC2 key label: y-coordinate. */
	private const LABEL_Y = -3;

	private function __construct(
		int $alg,
		public int $crv,
		public Bytes $x,
		public Bytes $y,
	) {
		parent::__construct($alg);
	}

	public static function fromCborMap(CborMap $map): self
	{
		return new self(
			$map->getInt(self::LABEL_ALG),
			$map->getInt(self::LABEL_CRV),
			$map->getBytes(self::LABEL_X),
			$map->getBytes(self::LABEL_Y),
		);
	}
}
