<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

/**
 * Base for the two authenticator responses returned by a credential.
 *
 * @see https://w3c.github.io/webauthn/#authenticatorresponse
 * @api
 */
abstract readonly class AuthenticatorResponse
{
    /**
     * @param string $clientDataJSON the raw JSON bytes as serialized by the client (base64url-decoded);
     *     kept verbatim because hashes and signatures are computed over these exact bytes
     */
    protected function __construct(
        public string $clientDataJSON,
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
