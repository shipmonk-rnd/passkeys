<?php declare(strict_types = 1);

namespace WebAuthnXTests\Ceremony;

use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;

/**
 * A trivial in-memory {@see CredentialStore} for the ceremony tests, standing in for the
 * relying party's real persistence.
 */
final class InMemoryCredentialStore implements CredentialStore
{
    /** @var array<string, CredentialRecord> */
    private array $records = [];

    public function add(CredentialRecord $record): void
    {
        $this->records[$record->credentialId] = $record;
    }

    public function findCredentialByCredentialId(string $credentialId): ?CredentialRecord
    {
        return $this->records[$credentialId] ?? null;
    }
}
