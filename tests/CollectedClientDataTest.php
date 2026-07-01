<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\Base64\Base64;
use WebAuthnX\CollectedClientData;
use WebAuthnX\Json\JsonObject;

use function json_encode;

use const JSON_THROW_ON_ERROR;

class CollectedClientDataTest extends WebAuthnTestCase
{
	public function testReadsAllMembers(): void
	{
		$clientData = new CollectedClientData(JsonObject::fromString(json_encode([
			'type' => 'webauthn.get',
			'challenge' => Base64::urlEncode('challenge-bytes'),
			'origin' => 'https://example.com',
			'topOrigin' => 'https://top.example.com',
			'crossOrigin' => true,
		], JSON_THROW_ON_ERROR)));

		self::assertSame('webauthn.get', $clientData->getType());
		self::assertSame('challenge-bytes', $clientData->getChallenge()->toBinaryString());
		self::assertSame('https://example.com', $clientData->getOrigin());
		self::assertSame('https://top.example.com', $clientData->getTopOrigin());
		self::assertTrue($clientData->getCrossOrigin());
	}

	public function testOmitsOptionalMembers(): void
	{
		$clientData = new CollectedClientData(JsonObject::fromString(json_encode([
			'type' => 'webauthn.create',
			'challenge' => Base64::urlEncode('challenge-bytes'),
			'origin' => 'https://example.com',
		], JSON_THROW_ON_ERROR)));

		self::assertSame('webauthn.create', $clientData->getType());
		self::assertNull($clientData->getTopOrigin());
		self::assertNull($clientData->getCrossOrigin());
	}
}
