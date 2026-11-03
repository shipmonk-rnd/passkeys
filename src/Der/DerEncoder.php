<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Der;

use LogicException;
use function array_slice;
use function base64_encode;
use function chr;
use function chunk_split;
use function explode;
use function implode;
use function ltrim;
use function ord;
use function pack;
use function preg_match;
use function strlen;

/**
 * A minimal DER encoder, scoped to what the library needs in order to hand a COSE key to ext-openssl
 * as a SubjectPublicKeyInfo ({@see \ShipMonk\Passkeys\Cose\CoseKey::verify()}): INTEGER, BIT STRING,
 * NULL, OBJECT IDENTIFIER and SEQUENCE, each with a definite length in its shortest form, plus the
 * PEM text form that ext-openssl loads.
 *
 * @see https://www.itu.int/rec/T-REC-X.690 X.690 §8 (encoding rules) and §10 (DER restrictions)
 * @internal an implementation detail of the PHP 8.1 support, not covered by the backward-compatibility promise
 */
final class DerEncoder
{

    /**
     * INTEGER from the big-endian bytes of a non-negative value (leading zero bytes are allowed).
     *
     * DER requires the shortest two's-complement form, so leading zero bytes are dropped and a
     * single zero byte is put back when the high bit is set, which would otherwise read as negative.
     */
    public static function encodeUnsignedInt(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '' || ord($bytes[0]) >= 0x80) {
            $bytes = "\x00{$bytes}";
        }

        return self::encode(0x02, $bytes);
    }

    /**
     * BIT STRING of whole bytes: the leading "unused bits" byte is always zero.
     */
    public static function encodeBitString(string $bytes): string
    {
        return self::encode(0x03, "\x00{$bytes}");
    }

    public static function encodeNull(): string
    {
        return self::encode(0x05, '');
    }

    /**
     * OBJECT IDENTIFIER given in dotted-decimal notation, e.g. "1.2.840.10045.2.1".
     *
     * @throws LogicException when the identifier is malformed (the library passes only constants, so that is a bug)
     */
    public static function encodeObjectIdentifier(string $oid): string
    {
        // At least two arcs, the first one 0, 1 or 2, each a canonical decimal (no leading zeros)
        // of at most 18 digits, so that no arithmetic below can overflow an int.
        $arc = '(0|[1-9][0-9]{0,17})';

        if (preg_match("~^([0-2])\\.{$arc}((?:\\.{$arc})*)\$~D", $oid, $matches) !== 1) {
            throw new LogicException("Invalid object identifier '{$oid}'");
        }

        [, $first, $second, $rest] = $matches;

        // The first two arcs share one subidentifier, 40 * first + second (X.690 §8.19.4), which is
        // unambiguous only when the second arc under the roots 0 and 1 stays below 40.
        if ($first !== '2' && (int) $second >= 40) {
            throw new LogicException("Invalid object identifier '{$oid}'");
        }

        $contents = self::encodeSubidentifier(40 * (int) $first + (int) $second);

        // $rest is either empty or ".arc.arc…", so the first exploded piece is always empty.
        foreach (array_slice(explode('.', $rest), 1) as $subsequentArc) {
            $contents .= self::encodeSubidentifier((int) $subsequentArc);
        }

        return self::encode(0x06, $contents);
    }

    /**
     * SEQUENCE of already encoded elements, in the given order.
     */
    public static function encodeSequence(string ...$elements): string
    {
        return self::encode(0x30, implode('', $elements));
    }

    /**
     * PEM text form of DER bytes, e.g. with the label "PUBLIC KEY": Base64 in lines of 64
     * characters between the BEGIN and END lines (RFC 7468 §2).
     */
    public static function toPem(
        string $label,
        string $der,
    ): string
    {
        return "-----BEGIN {$label}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$label}-----\n";
    }

    /**
     * Identifier octet, length octets and contents (X.690 §8.1). A length below 128 takes the short
     * form, a longer one the long form with no leading zero bytes (X.690 §8.1.3, §10.1).
     */
    private static function encode(
        int $tag,
        string $contents,
    ): string
    {
        $length = strlen($contents);

        if ($length < 0x80) {
            return chr($tag) . chr($length) . $contents;
        }

        $lengthBytes = ltrim(pack('J', $length), "\x00");

        return chr($tag) . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $contents;
    }

    /**
     * Base-128 digits, most significant first, with the high bit set on all but the last
     * (X.690 §8.19.2).
     */
    private static function encodeSubidentifier(int $value): string
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
