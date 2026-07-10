<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Cbor;

use ShipMonk\WebAuthn\Cbor\CborEncoder;
use function is_int;

/**
 * Builds CBOR test fixtures (COSE keys, attestation objects) on top of {@see CborEncoder},
 * adding the encodings only tests need: text strings and integer-keyed maps.
 */
final class CborTestEncoder
{

    /**
     * Major type 0/1: a (signed) integer.
     */
    public static function int(int $value): string
    {
        return CborEncoder::encodeInt($value);
    }

    /**
     * Major type 2: a byte string.
     */
    public static function byteString(string $bytes): string
    {
        return CborEncoder::encodeByteString($bytes);
    }

    /**
     * Major type 3: a UTF-8 text string.
     */
    public static function textString(string $text): string
    {
        return CborEncoder::encodeTextString($text);
    }

    /**
     * Major type 5: a map of already-encoded (key, value) byte pairs, kept in the given order.
     *
     * @param list<array{string, string}> $pairs
     */
    public static function map(array $pairs): string
    {
        return CborEncoder::encodeMap($pairs);
    }

    /**
     * An integer-keyed map, as used by COSE keys: integer values encode as CBOR
     * integers, string values as CBOR byte strings.
     *
     * @param array<int, int|string> $entries
     */
    public static function intMap(array $entries): string
    {
        $pairs = [];

        foreach ($entries as $key => $value) {
            $pairs[] = [self::int($key), is_int($value) ? self::int($value) : self::byteString($value)];
        }

        return self::map($pairs);
    }

}
