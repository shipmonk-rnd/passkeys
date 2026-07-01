<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Json\JsonObject;

/**
 * @see https://w3c.github.io/webauthn/#authenticatorattestationresponse
 */
final readonly class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
	private function __construct(
		Bytes $clientDataJSON,
		public Bytes $attestationObject,
	) {
		parent::__construct($clientDataJSON);
	}

	public static function fromJsonObject(JsonObject $jsonObject): self
	{
		return new self(
			$jsonObject->getBytes('clientDataJSON'),
			$jsonObject->getBytes('attestationObject'),
		);
	}

	public function parseAttestationObject(): AttestationObject
	{
		return BytesReader::read($this->attestationObject, static function (BytesReader $reader): AttestationObject {
			return AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
		});
	}
}
