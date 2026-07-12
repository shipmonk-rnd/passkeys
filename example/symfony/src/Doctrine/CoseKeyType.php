<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Doctrine;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use RuntimeException;
use ShipMonk\Passkeys\Cose\CoseKey;
use function base64_decode;
use function base64_encode;

/**
 * A Doctrine type that maps the credential's public key — a {@see CoseKey} value object — to a TEXT
 * column, storing the library's canonical {@see CoseKey::toBytes()} encoding as base64 and
 * rehydrating it with {@see CoseKey::fromBytes()} on read.
 *
 * Modelling the column as `CoseKey` (rather than a raw string the entity would have to decode
 * itself) keeps the round-trip in one place and lets {@see \ShipMonk\PasskeysSymfonyDemo\Entity\Credential}
 * expose a real {@see CoseKey} — exactly what a {@see \ShipMonk\Passkeys\Ceremony\CredentialRecord}
 * wants.
 */
final class CoseKeyType extends Type
{

    public const string NAME = 'cose_key';

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        return $platform->getClobTypeDeclarationSQL($column);
    }

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if ($value === null) {
            return null;
        }

        if (!$value instanceof CoseKey) {
            throw new RuntimeException('Expected a ' . CoseKey::class . ' instance');
        }

        return base64_encode($value->toBytes());
    }

    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): ?CoseKey
    {
        if ($value === null) {
            return null;
        }

        $decoded = base64_decode((string) $value, strict: true);

        if ($decoded === false) {
            throw new RuntimeException('Stored public key is not valid base64');
        }

        return CoseKey::fromBytes($decoded);
    }

}
