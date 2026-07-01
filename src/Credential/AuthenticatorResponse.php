<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\Bytes;

/**
 * Base for the two authenticator responses returned by a credential.
 *
 * @see https://w3c.github.io/webauthn/#authenticatorresponse
 * @api
 */
abstract readonly class AuthenticatorResponse
{
	protected function __construct(
		public Bytes $clientDataJSON,
	) {
	}

	/**
	 * @throws MalformedDataException
	 */
	public function parseClientData(): CollectedClientData
	{
		return CollectedClientData::fromBytes($this->clientDataJSON);
	}
}
