<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Base64\InvalidBase64Exception;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Binary\BytesReaderException;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Cbor\InvalidCborException;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;

/**
 * @see https://w3c.github.io/webauthn/#authenticatorattestationresponse
 * @api
 */
final readonly class AuthenticatorAttestationResponse extends AuthenticatorResponse
{
	/**
	 * @param  list<string>|null $transports the authenticator's transports as reported by the
	 *     client; unlike the rest of the response it cannot be recovered from the attestation
	 *     object, and a relying party stores it to seed `allowCredentials` on later assertions.
	 */
	private function __construct(
		Bytes $clientDataJSON,
		public Bytes $attestationObject,
		public ?array $transports,
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

		} catch (BytesReaderException | InvalidCborException | CborMapException $e) {
			throw new MalformedDataException('Malformed attestation object', $e);
		}
	}
}
