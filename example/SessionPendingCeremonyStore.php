<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysDemo;

use ShipMonk\Passkeys\PendingAuthentication;
use ShipMonk\Passkeys\PendingCeremonyStore;
use ShipMonk\Passkeys\PendingRegistration;
use function array_key_exists;
use function array_shift;
use function count;

/**
 * The demo's {@see PendingCeremonyStore}: pending ceremonies live in the PHP session — the right
 * scope, since a ceremony belongs to one browser session — keyed by the raw challenge bytes (PHP
 * arrays and session serialization are binary-safe) and capped so a page that keeps requesting
 * options cannot grow the session unboundedly. Each ceremony is stored as its whole
 * {@see PendingAuthentication} / {@see PendingRegistration} object, so no field — such as a
 * registration's `conditionalMediation` flag — is lost on the round-trip.
 */
final class SessionPendingCeremonyStore implements PendingCeremonyStore
{

    /**
     * How many unfinished ceremonies to keep per browser session (oldest dropped first).
     */
    private const int MAX_PENDING = 8;

    public function rememberPendingAuthentication(PendingAuthentication $pending): void
    {
        $_SESSION['pending_authentications'][$pending->challenge] = $pending;

        while (count($_SESSION['pending_authentications']) > self::MAX_PENDING) {
            array_shift($_SESSION['pending_authentications']);
        }
    }

    public function consumePendingAuthentication(string $challenge): ?PendingAuthentication
    {
        if (!array_key_exists($challenge, $_SESSION['pending_authentications'] ?? [])) {
            return null;
        }

        $pending = $_SESSION['pending_authentications'][$challenge];
        unset($_SESSION['pending_authentications'][$challenge]);

        return $pending;
    }

    public function rememberPendingRegistration(PendingRegistration $pending): void
    {
        $_SESSION['pending_registrations'][$pending->challenge] = $pending;

        while (count($_SESSION['pending_registrations']) > self::MAX_PENDING) {
            array_shift($_SESSION['pending_registrations']);
        }
    }

    public function consumePendingRegistration(string $challenge): ?PendingRegistration
    {
        if (!array_key_exists($challenge, $_SESSION['pending_registrations'] ?? [])) {
            return null;
        }

        $pending = $_SESSION['pending_registrations'][$challenge];
        unset($_SESSION['pending_registrations'][$challenge]);

        return $pending;
    }

}
