<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Credential;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Binary\BytesReader;
use ShipMonk\Passkeys\Cbor\CborMap;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Credential\AttestationObject;
use ShipMonk\Passkeys\Credential\AttestedCredentialData;
use ShipMonk\Passkeys\Credential\AuthenticatorData;
use ShipMonk\Passkeys\Credential\MalformedDataException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function str_repeat;
use function strlen;

#[CoversClass(AuthenticatorData::class)]
#[CoversClass(AttestationObject::class)]
#[CoversClass(AttestedCredentialData::class)]
final class AuthenticatorDataTest extends PasskeysTestCase
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

    /**
     * All flags clear: every predicate must report false. Each one tests its own bit, so a
     * predicate that ignored the mask (or compared against the wrong value) would answer true here.
     */
    public function testNoFlagsSet(): void
    {
        $authenticatorData = AuthenticatorData::fromBytes(
            self::bytesFromHex(str_repeat('00', 32) . '0000000000'),
        );

        self::assertSame(0, $authenticatorData->flags);
        self::assertFalse($authenticatorData->isUserPresent());
        self::assertFalse($authenticatorData->isUserVerified());
        self::assertFalse($authenticatorData->isBackupEligible());
        self::assertFalse($authenticatorData->isBackupState());
        self::assertFalse($authenticatorData->hasAttestedCredentialData());
        self::assertFalse($authenticatorData->hasExtensionData());
    }

    /**
     * Only the User Present bit: the neighbouring predicates must not answer to it.
     */
    public function testOnlyUserPresentFlagSet(): void
    {
        $authenticatorData = AuthenticatorData::fromBytes(
            self::bytesFromHex(str_repeat('00', 32) . '0100000000'),
        );

        self::assertTrue($authenticatorData->isUserPresent());
        self::assertFalse($authenticatorData->isUserVerified());
        self::assertFalse($authenticatorData->isBackupEligible());
        self::assertFalse($authenticatorData->isBackupState());
    }

    public function testFromBytesRejectsTruncatedData(): void
    {
        // Fewer than the 32 rpIdHash bytes: the underlying read failure is repacked as MalformedDataException.
        self::assertException(
            MalformedDataException::class,
            'Malformed authenticator data',
            static fn () => AuthenticatorData::fromBytes(self::bytesFromHex('000102')),
        );
    }

    /**
     * Every failure the nested parsers can raise — a truncated read, CBOR that is well-formed but
     * not a map, undecodable CBOR, and a syntactically fine COSE key of an unsupported type — has
     * to surface as the same MalformedDataException rather than leaking out of the parser.
     */
    #[DataProvider('provideMalformedAuthenticatorData')]
    public function testFromBytesRejectsEveryNestedParseFailure(string $hex): void
    {
        self::assertException(
            MalformedDataException::class,
            'Malformed authenticator data',
            static fn () => AuthenticatorData::fromBytes(self::bytesFromHex($hex)),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedAuthenticatorData(): iterable
    {
        $rpIdHash = str_repeat('00', 32);

        // flags 0x81 (UP + ED), signCount, then the extensions CBOR.
        yield 'extensions are not a CBOR map' => [$rpIdHash . ' 81 00000000 01'];
        yield 'extensions are undecodable CBOR' => [$rpIdHash . ' 81 00000000 f93c00'];

        // flags 0x41 (UP + AT), signCount, aaguid(16), credentialIdLength(2), credentialId, COSE key.
        yield 'attested credential key of an unsupported COSE type' => [
            $rpIdHash . ' 41 00000000 ' . str_repeat('01', 16) . ' 0010 ' . str_repeat('02', 16) . ' a1011863',
        ];
        yield 'attested credential data is truncated' => [
            $rpIdHash . ' 41 00000000 ' . str_repeat('01', 16) . ' 0010',
        ];
    }

}
