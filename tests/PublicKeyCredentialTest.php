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
			],
		], JSON_THROW_ON_ERROR)));

		self::assertSame(PublicKeyCredentialType::PUBLIC_KEY, $credential->type);
		self::assertSame(Base64::urlEncode('credential-id'), $credential->id);
		self::assertSame('credential-id', $credential->rawId->toBinaryString());
		self::assertSame('platform', $credential->authenticatorAttachment);
		self::assertNotNull($credential->clientExtensionResults);

		$response = $credential->response;
		self::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
		self::assertSame('none', $response->parseAttestationObject()->fmt);
		self::assertSame('webauthn.create', $response->parseClientData()->getType());
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
}
