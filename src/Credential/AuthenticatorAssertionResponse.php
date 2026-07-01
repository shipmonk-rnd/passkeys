<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Base64\InvalidBase64Exception;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;

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

	/**
	 * @throws JsonObjectException
	 * @throws InvalidBase64Exception
	 */
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
