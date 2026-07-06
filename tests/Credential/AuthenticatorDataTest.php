<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Credential;

use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Binary\BytesReader;
use ShipMonk\WebAuthn\Cbor\CborMap;
use ShipMonk\WebAuthn\Cose\CoseAlgorithmIdentifier;
use ShipMonk\WebAuthn\Cose\CoseEc2Key;
use ShipMonk\WebAuthn\Credential\AttestationObject;
use ShipMonk\WebAuthn\Credential\AuthenticatorData;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;
use function str_repeat;
use function strlen;

class AuthenticatorDataTest extends WebAuthnTestCase
{

    public function testFromBytes(): void
    {
        $attestationObjectBase64Url = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPicKuaB2QMLvuZJAXn8nWNe4Y2iZKLDmWiYb0qo0l5fpQECAyYgASFYICAFU4dQcXT_GH1hZV2JoHHdVUCU_AkgGFd20UpKqAM0IlggJQzogT8UjnN7-tKvzIGk8e5OdWX1xurwC_sffQKh1a0';
        $bytes = Base64::urlDecode($attestationObjectBase64Url);

        $attestationObject = BytesReader::read($bytes, static function (BytesReader $reader): AttestationObject {
            return AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
        });

        self::assertSame('none', $attestationObject->fmt);

        $authenticatorData = $attestationObject->parseAuthenticatorData();

        self::assertSame(32, strlen($authenticatorData->rpIdHash));
        self::assertSame(0, $authenticatorData->signCount);
        self::assertNull($authenticatorData->extensions);

        // flags 0x45: user present + user verified + attested credential data
        self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_USER_PRESENT);
        self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_USER_VERIFIED);
        self::assertNotSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA);
        self::assertSame(0, $authenticatorData->flags & AuthenticatorData::FLAG_EXTENSION_DATA);

        self::assertTrue($authenticatorData->isUserPresent());
        self::assertTrue($authenticatorData->isUserVerified());
        self::assertFalse($authenticatorData->isBackupEligible());
        self::assertFalse($authenticatorData->isBackupState());
        self::assertTrue($authenticatorData->hasAttestedCredentialData());
        self::assertFalse($authenticatorData->hasExtensionData());

        $attestedCredentialData = $authenticatorData->attestedCredentialData;
        self::assertNotNull($attestedCredentialData);
        self::assertSame(16, strlen($attestedCredentialData->aaGuid));
        self::assertSame(32, strlen($attestedCredentialData->credentialId));

        $credentialPublicKey = $attestedCredentialData->credentialPublicKey;
        self::assertInstanceOf(CoseEc2Key::class, $credentialPublicKey);
        self::assertSame(CoseAlgorithmIdentifier::ES256, $credentialPublicKey->alg);
        self::assertSame(1, $credentialPublicKey->crv);
        self::assertSame(32, strlen($credentialPublicKey->x));
        self::assertSame(32, strlen($credentialPublicKey->y));
    }

    /**
     * Minimal assertion authenticator data (no attested credential data, no extensions) with the
     * backup-eligible and backup-state flags set: rpIdHash(32) || flags(0x1D) || signCount(4).
     */
    public function testBackupFlags(): void
    {
        $authenticatorData = AuthenticatorData::fromBytes(
            self::bytesFromHex(str_repeat('00', 32) . '1d00000000'),
        );

        self::assertTrue($authenticatorData->isUserPresent());
        self::assertTrue($authenticatorData->isUserVerified());
        self::assertTrue($authenticatorData->isBackupEligible());
        self::assertTrue($authenticatorData->isBackupState());
        self::assertFalse($authenticatorData->hasAttestedCredentialData());
        self::assertNull($authenticatorData->attestedCredentialData);
        self::assertFalse($authenticatorData->hasExtensionData());
        self::assertNull($authenticatorData->extensions);
    }

    /**
     * Authenticator data with the extension-data flag set but no attested credential data:
     * rpIdHash(32) || flags(0x81 = UP+ED) || signCount(4) || CBOR extensions (empty map 0xA0).
     */
    public function testExtensionDataWithoutAttestedCredentialData(): void
    {
        $authenticatorData = AuthenticatorData::fromBytes(
            self::bytesFromHex(str_repeat('00', 32) . '8100000000a0'),
        );

        self::assertTrue($authenticatorData->isUserPresent());
        self::assertFalse($authenticatorData->hasAttestedCredentialData());
        self::assertNull($authenticatorData->attestedCredentialData);
        self::assertTrue($authenticatorData->hasExtensionData());
        self::assertNotNull($authenticatorData->extensions);
    }

}
