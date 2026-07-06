<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Base64\InvalidBase64Exception;
use WebAuthnX\Enum\AuthenticatorAttachment;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;

/**
 * The credential returned by the browser's `navigator.credentials` API, in its JSON form
 * ({@link https://w3c.github.io/webauthn/#dictdef-registrationresponsejson RegistrationResponseJSON} /
 * {@link https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson AuthenticationResponseJSON}).
 *
 * @template T of AuthenticatorResponse
 * @see https://w3c.github.io/webauthn/#iface-pkcredential
 * @api
 */
final readonly class PublicKeyCredential
{
	/**
	 * @param  T      $response
	 * @param  string $rawId raw credential id bytes ({@see $id} is its base64url form)
	 * @param  AuthenticatorAttachment|null $authenticatorAttachment null when the client sent none
	 *     or an unknown value (the spec instructs relying parties to treat unknown values as null)
	 */
	private function __construct(
		public string $id,
		public string $rawId,
		public string $type,
		public AuthenticatorResponse $response,
		public ?AuthenticatorAttachment $authenticatorAttachment,
		public ?JsonObject $clientExtensionResults,
	) {
	}

	/**
	 * Parses the JSON returned after a registration ceremony (`navigator.credentials.create()`).
	 *
	 * @return self<AuthenticatorAttestationResponse>
	 * @throws MalformedDataException
	 */
	public static function fromRegistrationResponseJson(JsonObject $jsonObject): self
	{
		try {
			return self::create(
				$jsonObject,
				AuthenticatorAttestationResponse::fromJsonObject($jsonObject->getObject('response')),
			);

		} catch (JsonObjectException | InvalidBase64Exception $e) {
			throw new MalformedDataException('Malformed registration response', $e);
		}
	}

	/**
	 * Parses the JSON returned after an authentication ceremony (`navigator.credentials.get()`).
	 *
	 * @return self<AuthenticatorAssertionResponse>
	 * @throws MalformedDataException
	 */
	public static function fromAuthenticationResponseJson(JsonObject $jsonObject): self
	{
		try {
			return self::create(
				$jsonObject,
				AuthenticatorAssertionResponse::fromJsonObject($jsonObject->getObject('response')),
			);

		} catch (JsonObjectException | InvalidBase64Exception $e) {
			throw new MalformedDataException('Malformed authentication response', $e);
		}
	}

	/**
	 * @template R of AuthenticatorResponse
	 * @param  R $response
	 * @return self<R>
	 * @throws JsonObjectException
	 * @throws InvalidBase64Exception
	 */
	private static function create(JsonObject $jsonObject, AuthenticatorResponse $response): self
	{
		$attachment = $jsonObject->getOptionalString('authenticatorAttachment');

		return new self(
			$jsonObject->getString('id'),
			$jsonObject->getBytes('rawId'),
			$jsonObject->getString('type'),
			$response,
			$attachment === null ? null : AuthenticatorAttachment::tryFrom($attachment),
			$jsonObject->getOptionalObject('clientExtensionResults'),
		);
	}
}
