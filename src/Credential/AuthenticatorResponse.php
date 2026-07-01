<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;

/**
 * Base for the two authenticator responses returned by a credential.
 *
 * @see https://w3c.github.io/webauthn/#authenticatorresponse
 */
abstract readonly class AuthenticatorResponse
{
	protected function __construct(
		public Bytes $clientDataJSON,
	) {
	}

	public function parseClientData(): CollectedClientData
	{
		return new CollectedClientData(JsonObject::fromBytes($this->clientDataJSON));
	}
}
