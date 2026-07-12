<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Doctrine;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use RuntimeException;
use function base64_decode;
use function base64_encode;

/**
 * A Doctrine type for a raw binary string — a WebAuthn user handle or credential id, arbitrary
 * bytes including NULs — stored base64-encoded in a TEXT column and returned as the raw bytes.
 *
 * Doctrine's built-in `binary` / `blob` types hand back a *stream resource* on read, which is
 * awkward for short, fixed identifiers you want to compare with `===`, use as array keys, or pass
 * straight to {@see \ShipMonk\Passkeys\PasskeyFlow} (which deals in raw-byte strings). Keeping the
 * value in a base64 TEXT column makes the PHP value an ordinary `string` and sidesteps the
 * BLOB-vs-TEXT comparison quirks SQLite has — the same reason the plain-PHP example base64-encodes
 * these columns by hand.
 */
final class BinaryStringType extends Type
{

    public const string NAME = 'binary_string';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        return $value === null ? null : base64_encode((string) $value);
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }

        $decoded = base64_decode((string) $value, strict: true);

        if ($decoded === false) {
            throw new RuntimeException('Stored value is not valid base64');
        }

        return $decoded;
    }

}
