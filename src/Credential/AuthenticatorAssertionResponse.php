<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;

/**
 * @see https://w3c.github.io/webauthn/#authenticatorassertionresponse
 */
final readonly class AuthenticatorAssertionResponse extends AuthenticatorResponse
{
	private function __construct(
		Bytes $clientDataJSON,
		public Bytes $authenticatorData,
		public Bytes $signature,
		public ?Bytes $userHandle,
	) {
		parent::__construct($clientDataJSON);
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
}
