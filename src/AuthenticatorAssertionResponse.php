<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;


final readonly class AuthenticatorAssertionResponse
{
	private function __construct(
		public Bytes $clientDataJSON,
		public Bytes $authenticatorData,
		public Bytes $signature,
		public ?Bytes $userHandle,
	) {
	}


	public static function fromJsonObject(JsonObject $jsonObject): self
	{
		return new self(
			$jsonObject->getBytes('clientDataJSON'),
			$jsonObject->getBytes('authenticatorData'),
			$jsonObject->getBytes('signature'),
			$jsonObject->getOptionalBytes('userHandle'),
		);
	}


	public function parseClientData(): CollectedClientData
	{
		return new CollectedClientData(JsonObject::fromBytes($this->clientDataJSON));
	}
}
