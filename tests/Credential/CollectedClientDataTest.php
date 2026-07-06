<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Credential;

use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Credential\CollectedClientData;
use ShipMonk\WebAuthn\Credential\MalformedDataException;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;
use function json_encode;
use const JSON_THROW_ON_ERROR;

class CollectedClientDataTest extends WebAuthnTestCase
{

    public function testReadsAllMembers(): void
    {
        $clientData = CollectedClientData::fromBytes(self::clientDataJson([
            'type' => 'webauthn.get',
            'challenge' => Base64::urlEncode('challenge-bytes'),
            'origin' => 'https://example.com',
            'topOrigin' => 'https://top.example.com',
            'crossOrigin' => true,
        ]));

        self::assertSame('webauthn.get', $clientData->getType());
        self::assertSame('challenge-bytes', $clientData->getChallenge());
        self::assertSame('https://example.com', $clientData->getOrigin());
        self::assertSame('https://top.example.com', $clientData->getTopOrigin());
        self::assertTrue($clientData->getCrossOrigin());
    }

    public function testOmitsOptionalMembers(): void
    {
        $clientData = CollectedClientData::fromBytes(self::clientDataJson([
            'type' => 'webauthn.create',
            'challenge' => Base64::urlEncode('challenge-bytes'),
            'origin' => 'https://example.com',
        ]));

        self::assertSame('webauthn.create', $clientData->getType());
        self::assertNull($clientData->getTopOrigin());
        self::assertNull($clientData->getCrossOrigin());
    }

    public function testRejectsInvalidJson(): void
    {
        $this->expectException(MalformedDataException::class);

        CollectedClientData::fromBytes('not json at all');
    }

    public function testRejectsMissingRequiredMember(): void
    {
        $this->expectException(MalformedDataException::class);

        CollectedClientData::fromBytes(self::clientDataJson([
            'challenge' => Base64::urlEncode('challenge-bytes'),
            'origin' => 'https://example.com',
        ]));
    }

    public function testRejectsNonCanonicalChallenge(): void
    {
        $this->expectException(MalformedDataException::class);

        CollectedClientData::fromBytes(self::clientDataJson([
            'type' => 'webauthn.get',
            'challenge' => 'not/valid/base64url',
            'origin' => 'https://example.com',
        ]));
    }

    /**
     * @param array<string, mixed> $members
     */
    private static function clientDataJson(array $members): string
    {
        return json_encode($members, JSON_THROW_ON_ERROR);
    }

}
