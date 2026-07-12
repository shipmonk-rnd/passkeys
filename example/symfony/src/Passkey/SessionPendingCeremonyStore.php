<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysSymfonyDemo\Passkey;

use ShipMonk\Passkeys\PendingAuthentication;
use ShipMonk\Passkeys\PendingCeremonyStore;
use ShipMonk\Passkeys\PendingRegistration;
use Symfony\Component\HttpFoundation\RequestStack;
use function array_key_exists;
use function array_shift;
use function count;

/**
 * The demo's {@see PendingCeremonyStore} on top of the Symfony session — the right scope, since a
 * ceremony belongs to one browser session. Pending ceremonies are kept keyed by the raw challenge
 * bytes (PHP session serialization is binary-safe), consumed (deleted) on use so each challenge is
 * single-use, and capped so a page that keeps requesting options cannot grow the session
 * unboundedly. The plain-PHP example does the same directly on `$_SESSION`.
 */
final class SessionPendingCeremonyStore implements PendingCeremonyStore
{

    /**
     * How many unfinished ceremonies to keep per browser session (oldest dropped first).
     */
    private const int MAX_PENDING = 8;

    private const string AUTHENTICATIONS_KEY = 'passkey_pending_authentications';
    private const string REGISTRATIONS_KEY = 'passkey_pending_registrations';

    public function __construct(
        private readonly RequestStack $requestStack,
    )
    {
    }

    public function rememberPendingAuthentication(PendingAuthentication $pending): void
    {
        $this->remember(self::AUTHENTICATIONS_KEY, $pending->challenge, $pending);
    }

    public function consumePendingAuthentication(string $challenge): ?PendingAuthentication
    {
        $pending = $this->consume(self::AUTHENTICATIONS_KEY, $challenge);

        return $pending instanceof PendingAuthentication ? $pending : null;
    }

    public function rememberPendingRegistration(PendingRegistration $pending): void
    {
        $this->remember(self::REGISTRATIONS_KEY, $pending->challenge, $pending);
    }

    public function consumePendingRegistration(string $challenge): ?PendingRegistration
    {
        $pending = $this->consume(self::REGISTRATIONS_KEY, $challenge);

        return $pending instanceof PendingRegistration ? $pending : null;
    }

    private function remember(
        string $key,
        string $challenge,
        PendingAuthentication|PendingRegistration $pending,
    ): void
    {
        $session = $this->requestStack->getSession();

        /** @var array<string, PendingAuthentication|PendingRegistration> $pendings */
        $pendings = $session->get($key, []);
        $pendings[$challenge] = $pending;

        while (count($pendings) > self::MAX_PENDING) {
            array_shift($pendings);
        }

        $session->set($key, $pendings);
    }

    private function consume(
        string $key,
        string $challenge,
    ): PendingAuthentication|PendingRegistration|null
    {
        $session = $this->requestStack->getSession();

        /** @var array<string, PendingAuthentication|PendingRegistration> $pendings */
        $pendings = $session->get($key, []);

        if (!array_key_exists($challenge, $pendings)) {
            return null;
        }

        $pending = $pendings[$challenge];
        unset($pendings[$challenge]);
        $session->set($key, $pendings);

        return $pending;
    }

}
