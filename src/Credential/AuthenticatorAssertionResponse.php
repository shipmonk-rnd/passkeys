<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Credential;

use ShipMonk\Passkeys\Base64\InvalidBase64Exception;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;

/**
 * @see https://w3c.github.io/webauthn/#authenticatorassertionresponse
 * @api
 */
final readonly class AuthenticatorAssertionResponse extends AuthenticatorResponse
{

    /**
     * @param string      $authenticatorData raw authenticator data bytes; parse with {@see AuthenticatorData::fromBytes()}
     * @param string      $signature         raw assertion signature bytes
     * @param string|null $userHandle        raw user handle bytes, if the authenticator returned one
     */
    private function __construct(
        string $clientDataJSON,
        public string $authenticatorData,
        public string $signature,
        public ?string $userHandle,
    )
    {
        parent::__construct($clientDataJSON);
    }

    /**
     * @throws InvalidBase64Exception
     * @throws JsonObjectException
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
