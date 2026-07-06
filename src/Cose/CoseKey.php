<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Binary\BytesReaderException;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Cbor\InvalidCborException;

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
	protected const int LABEL_KTY = 1;

	/** Common COSE key label: algorithm (alg). */
	protected const int LABEL_ALG = 3;

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
			return BytesReader::read(
				$bytes,
				static fn (BytesReader $reader): CoseKey => self::fromCborMap(CborMap::fromBytesReader($reader)),
			);

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
}
