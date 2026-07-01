<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;

/**
 * The credential returned by the browser's `navigator.credentials` API, in its JSON form
 * ({@link https://w3c.github.io/webauthn/#dictdef-registrationresponsejson RegistrationResponseJSON} /
 * {@link https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson AuthenticationResponseJSON}).
 *
 * @template T of AuthenticatorResponse
 * @see https://w3c.github.io/webauthn/#iface-pkcredential
 */
final readonly class PublicKeyCredential
{
	/**
	 * @param  T $response
	 */
	private function __construct(
		public string $id,
		public Bytes $rawId,
		public string $type,
		public AuthenticatorResponse $response,
		public ?string $authenticatorAttachment,
		public ?JsonObject $clientExtensionResults,
	) {
	}

	/**
	 * Parses the JSON returned after a registration ceremony (`navigator.credentials.create()`).
	 *
	 * @return self<AuthenticatorAttestationResponse>
	 * @throws JsonObjectException
	 */
	public static function fromRegistrationResponseJson(JsonObject $jsonObject): self
	{
		return self::create(
			$jsonObject,
			AuthenticatorAttestationResponse::fromJsonObject($jsonObject->getObject('response')),
		);
	}

	/**
	 * Parses the JSON returned after an authentication ceremony (`navigator.credentials.get()`).
	 *
	 * @return self<AuthenticatorAssertionResponse>
	 * @throws JsonObjectException
	 */
	public static function fromAuthenticationResponseJson(JsonObject $jsonObject): self
	{
		return self::create(
			$jsonObject,
			AuthenticatorAssertionResponse::fromJsonObject($jsonObject->getObject('response')),
		);
	}

	/**
	 * @template R of AuthenticatorResponse
	 * @param  R $response
	 * @return self<R>
	 * @throws JsonObjectException
	 */
	private static function create(JsonObject $jsonObject, AuthenticatorResponse $response): self
	{
		return new self(
			$jsonObject->getString('id'),
			$jsonObject->getBytes('rawId'),
			$jsonObject->getString('type'),
			$response,
			$jsonObject->getOptionalString('authenticatorAttachment'),
			$jsonObject->getOptionalObject('clientExtensionResults'),
		);
	}
}
