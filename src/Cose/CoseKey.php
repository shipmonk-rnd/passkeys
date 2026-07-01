<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Cbor\CborMap;

abstract class CoseKey
{

	private const KEY_KTY = 1;
	private const KEY_ALG = 3;

	protected function __construct(
		public int $kty,
		public int $alg,
		public ?int $crv,
		public ?string $x,
		public ?string $y,
		public ?string $n,
		public ?string $e,
	) {
	}


	public static function fromCborMap(CborMap $cborMap): CoseKey
	{
		// kty (1): 2 (EC2)
		// alg (3): -7 (ES256)

		return new static(
			$cborMap->getInt(self::KEY_KTY),
			$cborMap->getInt(self::KEY_ALG),
			$cborMap->getInt('-1'),
			$cborMap->getOptionalBytes('-2'),
			$cborMap->getOptionalBytes('-3'),
			$cborMap->getOptionalBytes('-1'),
			$cborMap->getOptionalBytes('-2'),
		);
	}
}
