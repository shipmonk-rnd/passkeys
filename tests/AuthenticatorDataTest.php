<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\AttestationObject;
use WebAuthnX\AuthenticatorData;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseEc2Key;


class AuthenticatorDataTest extends WebAuthnTestCase
{
	public function testFromBytes(): void
	{
		$attestationObjectBase64Url = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPicKuaB2QMLvuZJAXn8nWNe4Y2iZKLDmWiYb0qo0l5fpQECAyYgASFYICAFU4dQcXT_GH1hZV2JoHHdVUCU_AkgGFd20UpKqAM0IlggJQzogT8UjnN7-tKvzIGk8e5OdWX1xurwC_sffQKh1a0';
		$bytes = Bytes::fromBinaryString(Base64::urlDecode($attestationObjectBase64Url));

		$attestationObject = BytesReader::read($bytes, static function (BytesReader $reader): AttestationObject {
			return AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
		});

		self::assertSame('none', $attestationObject->fmt);

		$authenticatorData = $attestationObject->parseAuthenticatorData();

		self::assertSame(32, $authenticatorData->rpIdHash->length);
		self::assertSame(0, $authenticatorData->signCount);
		self::assertNull($authenticatorData->extensions);

		// flags 0x45: user present + user verified + attested credential data
		self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_USER_PRESENT);
		self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_USER_VERIFIED);
		self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA);
		self::assertSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_EXTENSION_DATA);

		$attestedCredentialData = $authenticatorData->attestedCredentialData;
		self::assertNotNull($attestedCredentialData);
		self::assertSame(16, $attestedCredentialData->aaGuid->length);
		self::assertSame(32, $attestedCredentialData->credentialId->length);

		$credentialPublicKey = $attestedCredentialData->credentialPublicKey;
		self::assertInstanceOf(CoseEc2Key::class, $credentialPublicKey);
		self::assertSame(CoseAlgorithmIdentifier::ES256, $credentialPublicKey->alg);
		self::assertSame(1, $credentialPublicKey->crv);
		self::assertSame(32, $credentialPublicKey->x->length);
		self::assertSame(32, $credentialPublicKey->y->length);
	}
}
