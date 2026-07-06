<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Base64;

use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Base64\InvalidBase64Exception;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;

class Base64Test extends WebAuthnTestCase
{

    #[DataProvider('provideRoundtrip')]
    public function testEncode(
        string $binary,
        string $encoded,
    ): void
    {
        self::assertSame($encoded, Base64::urlEncode($binary));
    }

    #[DataProvider('provideRoundtrip')]
    public function testDecode(
        string $binary,
        string $encoded,
    ): void
    {
        self::assertSame($binary, Base64::urlDecode($encoded));
    }

    /**
     * @return iterable<array{string, string}>
     */
    public static function provideRoundtrip(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'single byte' => ["\x00", 'AA'];
        yield 'no padding needed' => ['foobar', 'Zm9vYmFy'];
        yield 'url-safe alphabet' => ["\xfb\xff\xfe", '-__-'];
        yield 'one pad char' => ['fooba', 'Zm9vYmE'];
        yield 'two pad chars' => ['foob', 'Zm9vYg'];
    }

    #[DataProvider('provideInvalid')]
    public function testDecodeInvalid(string $encoded): void
    {
        self::assertException(
            InvalidBase64Exception::class,
            'Invalid base64url data',
            static fn () => Base64::urlDecode($encoded),
        );
    }

    /**
     * @return iterable<array{string}>
     */
    public static function provideInvalid(): iterable
    {
        yield 'space' => ['ab cd'];
        yield 'exclamation' => ['!!!!'];
        yield 'standard base64 plus' => ['+//+'];
        yield 'standard base64 padding' => ['Zm9vYmE='];
        yield 'invalid length (mod 4 == 1)' => ['a'];
    }

    /**
     * Inputs with the correct alphabet/length but non-zero unused trailing bits: they decode
     * (base64_decode is lenient here) but re-encode to a different string, so we reject them.
     * 'QR' decodes to 0x41 (canonical 'QQ'); 'Zm9vYmF' decodes to 'fooba' (canonical 'Zm9vYmE').
     */
    #[DataProvider('provideNonCanonical')]
    public function testDecodeRejectsNonCanonical(string $encoded): void
    {
        self::assertException(
            InvalidBase64Exception::class,
            'Non-canonical base64url data',
            static fn () => Base64::urlDecode($encoded),
        );
    }

    /**
     * @return iterable<array{string}>
     */
    public static function provideNonCanonical(): iterable
    {
        yield 'two-char group' => ['QR'];
        yield 'three-char group' => ['Zm9vYmF'];
    }

}
