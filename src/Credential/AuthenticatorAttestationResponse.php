<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Credential;

use ShipMonk\Passkeys\Base64\InvalidBase64Exception;
use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Binary\BytesReaderException;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cbor\CborMapException;
use ShipMonk\Passkeys\Cbor\InvalidCborException;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;

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
