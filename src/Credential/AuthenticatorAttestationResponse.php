<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthn\Credential;

use ShipMonk\WebAuthn\Base64\InvalidBase64Exception;
use ShipMonk\WebAuthn\Binary\BytesReader;
use ShipMonk\WebAuthn\Binary\BytesReaderException;
use ShipMonk\WebAuthn\Cbor\CborMap;
use ShipMonk\WebAuthn\Cbor\CborMapException;
use ShipMonk\WebAuthn\Cbor\InvalidCborException;
use ShipMonk\WebAuthn\Json\JsonObject;
use ShipMonk\WebAuthn\Json\JsonObjectException;

/**
 * @see https://w3c.github.io/webauthn/#authenticatorattestationresponse
 * @api
 */
final readonly class AuthenticatorAttestationResponse extends AuthenticatorResponse
{

    /**
     * @param string            $attestationObject raw CBOR bytes of the attestation object; parse with {@see self::parseAttestationObject()}
     * @param list<string>|null $transports        the authenticator's transports as reported by the
     *            client; unlike the rest of the response it cannot be recovered from the attestation
     *            object, and a relying party stores it to seed `allowCredentials` on later assertions.
     */
    private function __construct(
        string $clientDataJSON,
        public string $attestationObject,
        public ?array $transports,
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
            $jsonObject->getBytes('attestationObject'),
            $jsonObject->getOptionalStringList('transports'),
        );
    }

    /**
     * @throws MalformedDataException
     */
    public function parseAttestationObject(): AttestationObject
    {
        try {
            return BytesReader::read($this->attestationObject, static function (BytesReader $reader): AttestationObject {
                return AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
            });

        } catch (BytesReaderException | CborMapException | InvalidCborException $e) {
            throw new MalformedDataException('Malformed attestation object', $e);
        }
    }

}
