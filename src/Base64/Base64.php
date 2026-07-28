<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Base64;

use function base64_decode;
use function base64_encode;
use function preg_match;
use function rtrim;
use function strtr;

/**
 * @see https://www.rfc-editor.org/rfc/rfc4648.html#section-5
 */
final class Base64
{

    public static function urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @throws InvalidBase64Exception
     */
    public static function urlDecode(string $data): string
    {
        // `\z` rather than `$`: PCRE's `$` also matches before a final newline, which would let a
        // trailing "\n" through the alphabet check (base64_decode() skips whitespace even in strict
        // mode, so it would then be caught only by the canonicality check below, and reported as
        // non-canonical rather than as the invalid character it is).
        if ($data !== '' && preg_match('~^[A-Za-z0-9_-]+\z~', $data) !== 1) {
            throw new InvalidBase64Exception('Invalid base64url data');
        }

        // No `=` padding is re-added: base64_decode() accepts unpadded input, and with the alphabet
        // check anchored above there is no input for which appending it changes the outcome.
        $base64 = strtr($data, '-_', '+/');

        $decoded = base64_decode($base64, strict: true);

        if ($decoded === false) {
            throw new InvalidBase64Exception('Invalid base64url data');
        }

        // base64_decode() accepts non-canonical input (non-zero unused trailing bits), so two
        // distinct strings can decode to the same bytes. WebAuthn requires canonical base64url,
        // so reject anything that does not round-trip back to its own encoding.
        if (self::urlEncode($decoded) !== $data) {
            throw new InvalidBase64Exception('Non-canonical base64url data');
        }

        return $decoded;
    }

}
