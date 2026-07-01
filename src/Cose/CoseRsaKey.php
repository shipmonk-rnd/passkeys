<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborMap;

/**
 * COSE key of type RSA, e.g. RS256.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8230.html#section-4 RSA key parameters
 */
final class CoseRsaKey extends CoseKey
{
	/** Key type value for RSA keys. */
	public const KTY = 3;

	/** RSA key label: modulus (n). */
	private const LABEL_N = -1;

	/** RSA key label: public exponent (e). */
	private const LABEL_E = -2;

	private function __construct(
		int $alg,
		public Bytes $n,
		public Bytes $e,
	) {
		parent::__construct($alg);
	}

	public static function fromCborMap(CborMap $map): self
	{
		return new self(
			$map->getInt(self::LABEL_ALG),
			$map->getBytes(self::LABEL_N),
			$map->getBytes(self::LABEL_E),
		);
	}
}
