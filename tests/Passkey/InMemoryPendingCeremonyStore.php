<?php declare(strict_types = 1);

namespace WebAuthnXTests\Passkey;

use WebAuthnX\Passkey\PendingAuthentication;
use WebAuthnX\Passkey\PendingCeremonyStore;
use WebAuthnX\Passkey\PendingRegistration;
use function base64_encode;

/**
 * A trivial in-memory {@see PendingCeremonyStore} for the flow tests, standing in for the relying
 * party's real session. The challenge-keyed maps are exposed so tests can assert which ceremonies
 * are pending and that consumption deletes them.
 */
final class InMemoryPendingCeremonyStore implements PendingCeremonyStore
{

    /**
     * @var array<string, PendingAuthentication> base64(challenge) → pending ceremony
     */
    public private(set) array $pendingAuthentications = [];

    /**
     * @var array<string, PendingRegistration> base64(challenge) → pending ceremony
     */
    public private(set) array $pendingRegistrations = [];

    public function rememberPendingAuthentication(PendingAuthentication $pending): void
    {
        $this->pendingAuthentications[base64_encode($pending->challenge)] = $pending;
    }

    public function consumePendingAuthentication(string $challenge): ?PendingAuthentication
    {
        $key = base64_encode($challenge);
        $pending = $this->pendingAuthentications[$key] ?? null;
        unset($this->pendingAuthentications[$key]);

        return $pending;
    }

    public function rememberPendingRegistration(PendingRegistration $pending): void
    {
        $this->pendingRegistrations[base64_encode($pending->challenge)] = $pending;
    }

    public function consumePendingRegistration(string $challenge): ?PendingRegistration
    {
        $key = base64_encode($challenge);
        $pending = $this->pendingRegistrations[$key] ?? null;
        unset($this->pendingRegistrations[$key]);

        return $pending;
    }

}
