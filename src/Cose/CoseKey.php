<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;

/**
 * A COSE_Key as used by WebAuthn credential public keys.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-7 COSE key structure
 * @see https://www.rfc-editor.org/rfc/rfc9053.html key type / algorithm parameters
 * @api
 */
abstract class CoseKey
{
	/** Common COSE key label: key type (kty). */
	protected const LABEL_KTY = 1;

	/** Common COSE key label: algorithm (alg). */
	protected const LABEL_ALG = 3;

	protected function __construct(
		public int $alg,
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
	 * Encodes this key as a DER-encoded SubjectPublicKeyInfo (RFC 5280 §4.1.2.7),
	 * the form consumed by {@see \openssl_pkey_get_public()}.
	 */
	abstract public function toDerSubjectPublicKeyInfo(): Bytes;
}
