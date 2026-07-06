<?php declare(strict_types = 1);

namespace WebAuthnXTests\Passkey;

use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Passkey\PasskeyStore;
use WebAuthnX\Passkey\RegisteredPasskey;

use function base64_encode;

/**
 * A trivial in-memory {@see PasskeyStore} for the flow tests, standing in for the relying party's
 * real user / credential tables. Users and credentials are seeded via {@see addUser()} /
 * {@see addCredential()}; every write the flow performs is captured for assertions.
 */
final class InMemoryPasskeyStore implements PasskeyStore
{
    /** @var array<string, string> username → raw user handle */
    private array $users = [];

    /** @var array<string, CredentialRecord> base64(credential id) → record */
    private array $credentials = [];

    /** @var list<AuthenticationResult> everything passed to updateCredential() */
    public private(set) array $updatedCredentials = [];

    /** @var list<RegisteredPasskey> everything passed to saveCredential() */
    public private(set) array $savedPasskeys = [];

    public function addUser(string $username, string $userHandle): void
    {
        $this->users[$username] = $userHandle;
    }

    public function addCredential(CredentialRecord $record): void
    {
        $this->credentials[base64_encode($record->credentialId)] = $record;
    }

    public function findCredentialByCredentialId(string $credentialId): ?CredentialRecord
    {
        return $this->credentials[base64_encode($credentialId)] ?? null;
    }

    public function findUserHandleByUsername(string $username): ?string
    {
        return $this->users[$username] ?? null;
    }

    public function findCredentialsByUserHandle(string $userHandle): array
    {
        $records = [];

        foreach ($this->credentials as $record) {
            if ($record->userHandle === $userHandle) {
                $records[] = $record;
            }
        }

        return $records;
    }

    public function saveCredential(RegisteredPasskey $passkey): void
    {
        $this->savedPasskeys[] = $passkey;
        $this->addCredential($passkey->toCredentialRecord());
    }

    public function updateCredential(AuthenticationResult $result): void
    {
        $this->updatedCredentials[] = $result;
    }
}
