<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Credential;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Credential\CollectedClientData;
use ShipMonk\Passkeys\Credential\MalformedDataException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_encode;
use const JSON_THROW_ON_ERROR;

#[CoversClass(CollectedClientData::class)]
#[CoversClass(MalformedDataException::class)]
final class CollectedClientDataTest extends PasskeysTestCase
{

    #[DataProvider('provideClientDataPrefixes')]
    public function testReadsAllMembers(string $prefix): void
    {
        $clientData = CollectedClientData::fromBytes($prefix . self::clientDataJson([
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

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideClientDataPrefixes(): iterable
    {
        yield 'no BOM' => [''];
        yield 'leading UTF-8 BOM' => ["\xEF\xBB\xBF"];
        yield 'leading UTF-8 BOM followed by JSON whitespace' => ["\xEF\xBB\xBF\r\n "];
    }

    public function testPreservesBomInsideJsonString(): void
    {
        $clientData = CollectedClientData::fromBytes(
            "\xEF\xBB\xBF" . '{"type":"webauthn.get","challenge":"YQ","origin":"https://example.com/' . "\xEF\xBB\xBF" . '"}',
        );

        self::assertSame("https://example.com/\xEF\xBB\xBF", $clientData->getOrigin());
    }

    #[DataProvider('provideMalformedBomClientData')]
    public function testRejectsMalformedBomClientData(string $json): void
    {
        $this->expectException(MalformedDataException::class);
        $this->expectExceptionMessage('Malformed client data');

        CollectedClientData::fromBytes($json);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedBomClientData(): iterable
    {
        $json = self::clientDataJson([
            'type' => 'webauthn.get',
            'challenge' => Base64::urlEncode('challenge-bytes'),
            'origin' => 'https://example.com',
        ]);

        yield 'repeated leading BOM' => ["\xEF\xBB\xBF\xEF\xBB\xBF" . $json];
        yield 'BOM after whitespace' => [" \xEF\xBB\xBF" . $json];
        yield 'trailing BOM' => [$json . "\xEF\xBB\xBF"];
        yield 'incomplete BOM' => ["\xEF\xBB" . $json];
        yield 'BOM followed by invalid JSON' => ["\xEF\xBB\xBFnot json"];
        yield 'BOM only' => ["\xEF\xBB\xBF"];
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
