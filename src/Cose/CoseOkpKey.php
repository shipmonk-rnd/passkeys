<?php declare(strict_types = 1);

namespace WebAuthnX\Cose;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cbor\CborEncoder;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Der\DerEncoder;

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
	public const KTY = 1;

	/** COSE curve identifier: Ed25519. */
	public const CRV_ED25519 = 6;

	/** OKP key label: curve (crv). */
	private const LABEL_CRV = -1;

	/** OKP key label: public key (x). */
	private const LABEL_X = -2;

	/** OID for id-Ed25519 (RFC 8410 §3); note it carries no algorithm parameters. */
	private const OID_ED25519 = '1.3.101.112';

	/**
	 * Maps each supported algorithm to its curve and public-key length in bytes.
	 */
	private const ALGORITHMS = [
		CoseAlgorithmIdentifier::EdDSA => [self::CRV_ED25519, 32],
	];

	private function __construct(
		int $alg,
		public int $crv,
		public Bytes $x,
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
		$x = $map->getBytes(self::LABEL_X);

		if (!isset(self::ALGORITHMS[$alg])) {
			throw new CoseKeyException("Unsupported OKP algorithm {$alg}");
		}

		[$expectedCrv, $keyLength] = self::ALGORITHMS[$alg];

		if ($crv !== $expectedCrv) {
			throw new CoseKeyException("OKP algorithm {$alg} requires curve {$expectedCrv}, got {$crv}");
		}

		if ($x->length !== $keyLength) {
			throw new CoseKeyException("OKP curve {$crv} requires {$keyLength}-byte public key");
		}

		return new self($alg, $crv, $x);
	}

	public function toBytes(): Bytes
	{
		return Bytes::fromBinaryString(CborEncoder::encodeMap([
			[CborEncoder::encodeInt(self::LABEL_KTY), CborEncoder::encodeInt(self::KTY)],
			[CborEncoder::encodeInt(self::LABEL_ALG), CborEncoder::encodeInt($this->alg)],
			[CborEncoder::encodeInt(self::LABEL_CRV), CborEncoder::encodeInt($this->crv)],
			[CborEncoder::encodeInt(self::LABEL_X), CborEncoder::encodeByteString($this->x->toBinaryString())],
		]));
	}

	public function toDerSubjectPublicKeyInfo(): Bytes
	{
		$spki = DerEncoder::encodeSequence(
			DerEncoder::encodeSequence(DerEncoder::encodeObjectIdentifier(self::OID_ED25519))
			. DerEncoder::encodeBitString($this->x->toBinaryString()),
		);

		return Bytes::fromBinaryString($spki);
	}
}
