<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Der;

use LogicException;
use function array_map;
use function chr;
use function count;
use function explode;
use function implode;
use function ltrim;
use function ord;
use function pack;
use function strlen;

class DerEncoder
{

    public static function encodeUnsignedInt(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if (strlen($bytes) === 0 || ord($bytes[0]) >= 0x80) {
            $bytes = "\x00{$bytes}";
        }

        return "\x02" . self::encodeLength(strlen($bytes)) . $bytes;
    }

    public static function encodeBitString(string $bytes): string
    {
        return "\x03" . self::encodeLength(strlen($bytes) + 1) . "\x00{$bytes}";
    }

    public static function encodeNull(): string
    {
        return "\x05\x00";
    }

    /**
     * Encodes an OBJECT IDENTIFIER given in dotted-decimal notation (e.g. "1.2.840.10045.2.1").
     */
    public static function encodeObjectIdentifier(string $oid): string
    {
        $arcs = array_map(static fn (string $arc): int => (int) $arc, explode('.', $oid));

        if (count($arcs) < 2 || $arcs[0] < 0 || $arcs[0] > 2 || $arcs[1] < 0) {
            throw new LogicException("Invalid object identifier '{$oid}'");
        }

        $content = self::encodeBase128($arcs[0] * 40 + $arcs[1]);

        for ($i = 2; $i < count($arcs); $i++) {
            if ($arcs[$i] < 0) {
                throw new LogicException("Invalid object identifier '{$oid}'");
            }

            $content .= self::encodeBase128($arcs[$i]);
        }

        return "\x06" . self::encodeLength(strlen($content)) . $content;
    }

    public static function encodeSequence(string ...$elements): string
    {
        $content = implode('', $elements);

        return "\x30" . self::encodeLength(strlen($content)) . $content;
    }

    /**
     * @param non-negative-int $length
     */
    public static function encodeLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $lengthBytes = ltrim(pack('J', $length), "\x00");
        return chr(0x80 | strlen($lengthBytes)) . $lengthBytes;
    }

    /**
     * Encodes a non-negative integer as a base-128 value with continuation bits,
     * as used for the arcs of an OBJECT IDENTIFIER.
     */
    private static function encodeBase128(int $value): string
    {
        $bytes = chr($value & 0x7F);
        $value >>= 7;

        while ($value > 0) {
            $bytes = chr(0x80 | ($value & 0x7F)) . $bytes;
            $value >>= 7;
        }

        return $bytes;
    }

}
