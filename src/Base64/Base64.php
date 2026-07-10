<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Base64;

use function base64_decode;
use function base64_encode;
use function preg_match;
use function rtrim;
use function str_repeat;
use function strlen;
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
        if ($data !== '' && preg_match('~^[A-Za-z0-9_-]+$~', $data) !== 1) {
            throw new InvalidBase64Exception('Invalid base64url data');
        }

        $base64 = strtr($data, '-_', '+/');
        $base64 .= str_repeat('=', (4 - strlen($base64) % 4) % 4);

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
