<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\AuthenticatorAssertionResponse;
use WebAuthnX\AuthenticatorAttestationResponse;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;
use WebAuthnX\PublicKeyCredential;
use WebAuthnX\PublicKeyCredentialType;

use function json_encode;

use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialTest extends WebAuthnTestCase
{
	private const ATTESTATION_OBJECT = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYql'
		. 'MGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPicKuaB2QMLvuZJAXn8nWNe4Y2iZKLDmWiYb0qo0l5fpQEC'
		. 'AyYgASFYICAFU4dQcXT_GH1hZV2JoHHdVUCU_AkgGFd20UpKqAM0IlggJQzogT8UjnN7-tKvzIGk8e5OdWX1xurwC_sffQKh1a0';

	public function testFromRegistrationResponseJson(): void
	{
		$clientDataJson = '{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}';

		$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode('credential-id'),
			'rawId' => Base64::urlEncode('credential-id'),
			'type' => 'public-key',
			'authenticatorAttachment' => 'platform',
			'clientExtensionResults' => (object) [],
			'response' => [
				'clientDataJSON' => Base64::urlEncode($clientDataJson),
				'attestationObject' => self::ATTESTATION_OBJECT,
				'transports' => ['internal', 'hybrid'],
			],
		], JSON_THROW_ON_ERROR)));

		self::assertSame(PublicKeyCredentialType::PUBLIC_KEY, $credential->type);
		self::assertSame(Base64::urlEncode('credential-id'), $credential->id);
		self::assertSame('credential-id', $credential->rawId->toBinaryString());
		self::assertSame('platform', $credential->authenticatorAttachment);
		self::assertNotNull($credential->clientExtensionResults);

		$response = $credential->response;
		self::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
		self::assertSame(['internal', 'hybrid'], $response->transports);
		self::assertSame('none', $response->parseAttestationObject()->fmt);
		self::assertSame('webauthn.create', $response->parseClientData()->getType());
	}

	public function testRegistrationResponseWithoutTransports(): void
	{
		$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode('credential-id'),
			'rawId' => Base64::urlEncode('credential-id'),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.create"}'),
				'attestationObject' => self::ATTESTATION_OBJECT,
			],
		], JSON_THROW_ON_ERROR)));

		self::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);
		self::assertNull($credential->response->transports);
	}

	public function testFromAuthenticationResponseJson(): void
	{
		$clientDataJson = '{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}';

		$credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode('credential-id'),
			'rawId' => Base64::urlEncode('credential-id'),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode($clientDataJson),
				'authenticatorData' => Base64::urlEncode('authenticator-data'),
				'signature' => Base64::urlEncode('signature-bytes'),
				'userHandle' => Base64::urlEncode('user-handle'),
			],
		], JSON_THROW_ON_ERROR)));

		self::assertSame(PublicKeyCredentialType::PUBLIC_KEY, $credential->type);
		self::assertNull($credential->authenticatorAttachment);
		self::assertNull($credential->clientExtensionResults);

		$response = $credential->response;
		self::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
		self::assertSame('signature-bytes', $response->signature->toBinaryString());
		self::assertSame('authenticator-data', $response->authenticatorData->toBinaryString());
		self::assertNotNull($response->userHandle);
		self::assertSame('user-handle', $response->userHandle->toBinaryString());
		self::assertSame('webauthn.get', $response->parseClientData()->getType());
	}

	public function testFromResponseJsonRejectsMissingResponse(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Missing key 'response' in JSON object",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromArray([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
			])),
		);
	}

	public function testFromResponseJsonRejectsNonObjectResponse(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'response' is not an object",
			static fn () => PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromArray([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => 'not-an-object',
			])),
		);
	}

	public function testFromAuthenticationResponseJsonWithoutUserHandle(): void
	{
		$credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode('credential-id'),
			'rawId' => Base64::urlEncode('credential-id'),
			'type' => 'public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.get"}'),
				'authenticatorData' => Base64::urlEncode('authenticator-data'),
				'signature' => Base64::urlEncode('signature-bytes'),
			],
		], JSON_THROW_ON_ERROR)));

		self::assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
		self::assertNull($credential->response->userHandle);
	}

	/**
	 * The parser does not validate the `type` string (consistent with how `AttestationObject`
	 * leaves `fmt` unchecked); the ceremony layer is responsible for rejecting an unexpected type.
	 */
	public function testAcceptsArbitraryType(): void
	{
		$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
			'id' => Base64::urlEncode('credential-id'),
			'rawId' => Base64::urlEncode('credential-id'),
			'type' => 'not-public-key',
			'response' => [
				'clientDataJSON' => Base64::urlEncode('{}'),
				'attestationObject' => Base64::urlEncode('x'),
			],
		], JSON_THROW_ON_ERROR)));

		self::assertSame('not-public-key', $credential->type);
	}

	public function testRejectsMissingTopLevelMember(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Missing key 'id' in JSON object",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'attestationObject' => Base64::urlEncode('x'),
				],
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsMissingClientDataJsonInResponse(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Missing key 'clientDataJSON' in JSON object",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => ['attestationObject' => Base64::urlEncode('x')],
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsMissingSignatureInResponse(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Missing key 'signature' in JSON object",
			static fn () => PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'authenticatorData' => Base64::urlEncode('authenticator-data'),
				],
			], JSON_THROW_ON_ERROR))),
		);
	}

	/**
	 * An explicit JSON null for a required object member is reported as missing (getObject uses
	 * isset semantics, for which JSON null is absent) — a null response is invalid either way.
	 */
	public function testRejectsNullResponse(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Missing key 'response' in JSON object",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => null,
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsNonStringAuthenticatorAttachment(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'authenticatorAttachment' is not a string",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'authenticatorAttachment' => 123,
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'attestationObject' => Base64::urlEncode('x'),
				],
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsNonStringType(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'type' is not a string",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 123,
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'attestationObject' => Base64::urlEncode('x'),
				],
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsNonArrayTransports(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'transports' is not an array",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'attestationObject' => Base64::urlEncode('x'),
					'transports' => 'usb',
				],
			], JSON_THROW_ON_ERROR))),
		);
	}

	public function testRejectsNonStringTransport(): void
	{
		self::assertException(
			JsonObjectException::class,
			"Value of key 'transports' is not an array of strings",
			static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
				'id' => Base64::urlEncode('credential-id'),
				'rawId' => Base64::urlEncode('credential-id'),
				'type' => 'public-key',
				'response' => [
					'clientDataJSON' => Base64::urlEncode('{}'),
					'attestationObject' => Base64::urlEncode('x'),
					'transports' => [1, 2],
				],
			], JSON_THROW_ON_ERROR))),
		);
	}
}
