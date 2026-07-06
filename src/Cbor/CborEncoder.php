<?php declare(strict_types = 1);

namespace WebAuthnX\Cbor;

use function chr;
use function count;
use function pack;
use function strlen;

/**
 * A minimal CBOR encoder — the inverse of {@see CborDecoder}, scoped to what the library needs in
 * order to re-serialise a COSE key ({@see \WebAuthnX\Cose\CoseKey::toBytes()}): signed integers,
 * byte strings, and an integer-keyed map. Encodings are definite-length; map entries are emitted in
 * the order given (the decoder is order-insensitive, so no canonical sort is required for a
 * round-trip).
 *
 * @see https://www.rfc-editor.org/rfc/rfc8949.html#section-3 CBOR data item head
 */
final class CborEncoder
{

    /**
     * Major type 0/1: a signed integer.
     */
    public static function encodeInt(int $value): string
    {
        return $value >= 0
            ? self::head(0, $value)
            : self::head(1, -1 - $value);
    }

    /**
     * Major type 2: a byte string.
     */
    public static function encodeByteString(string $bytes): string
    {
        return self::head(2, strlen($bytes)) . $bytes;
    }

    /**
     * Major type 5: a map of already-encoded (key, value) byte pairs, in the given order.
     *
     * @param list<array{string, string}> $pairs
     */
    public static function encodeMap(array $pairs): string
    {
        $body = '';

        foreach ($pairs as [$key, $value]) {
            $body .= $key . $value;
        }

        return self::head(5, count($pairs)) . $body;
    }

    /**
     * Encodes a data item head: the major type in the top 3 bits, then the argument either inline
     * (< 24) or in a following 1/2/4/8-byte big-endian field. The argument is always non-negative
     * (a length, count, or the unsigned magnitude of an integer).
     *
     * @param int<0, 7> $majorType
     */
    private static function head(
        int $majorType,
        int $value,
    ): string
    {
        $initialByte = $majorType << 5;

        if ($value < 24) {
            return chr($initialByte | $value);
        }

        if ($value <= 0xFF) {
            return chr($initialByte | 24) . chr($value);
        }

        if ($value <= 0xFFFF) {
            return chr($initialByte | 25) . pack('n', $value);
        }

        if ($value <= 0xFFFFFFFF) {
            return chr($initialByte | 26) . pack('N', $value);
        }

        return chr($initialByte | 27) . pack('J', $value);
    }

}
