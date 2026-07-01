<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Json\JsonObject;

final readonly class AuthenticatorAttestationResponse
{
	private function __construct(
		public Bytes $clientDataJSON,
		public Bytes $attestationObject,
	) {
	}

	public static function fromJsonObject(JsonObject $jsonObject): self
	{
		return new self(
			$jsonObject->getBytes('clientDataJSON'),
			$jsonObject->getBytes('attestationObject'),
		);
	}

	public function parseClientData(): CollectedClientData
	{
		return new CollectedClientData(JsonObject::fromBytes($this->clientDataJSON));
	}

	public function parseAttestationObject(): AttestationObject
	{
		return BytesReader::read($this->attestationObject, static function (BytesReader $reader): AttestationObject {
			return AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
		});
	}
}
