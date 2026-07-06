<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use WebAuthnX\Passkey\PendingAuthentication;
use WebAuthnX\Passkey\PendingCeremonyStore;
use WebAuthnX\Passkey\PendingRegistration;

use function array_key_exists;
use function array_shift;
use function count;

/**
 * The demo's {@see PendingCeremonyStore}: pending ceremonies live in the PHP session — the right
 * scope, since a ceremony belongs to one browser session — keyed by the raw challenge bytes (PHP
 * arrays and session serialization are binary-safe) and capped so a page that keeps requesting
 * options cannot grow the session unboundedly.
 */
final class SessionPendingCeremonyStore implements PendingCeremonyStore
{
    /** How many unfinished ceremonies to keep per browser session (oldest dropped first). */
    private const int MAX_PENDING = 8;

    public function rememberPendingAuthentication(PendingAuthentication $pending): void
    {
        $_SESSION['pending_authentications'][$pending->challenge] = $pending->userHandle;

        while (count($_SESSION['pending_authentications']) > self::MAX_PENDING) {
            array_shift($_SESSION['pending_authentications']);
        }
    }

    public function consumePendingAuthentication(string $challenge): ?PendingAuthentication
    {
        if (!array_key_exists($challenge, $_SESSION['pending_authentications'] ?? [])) {
            return null;
        }

        $userHandle = $_SESSION['pending_authentications'][$challenge];
        unset($_SESSION['pending_authentications'][$challenge]);

        return new PendingAuthentication($challenge, $userHandle);
    }

    public function rememberPendingRegistration(PendingRegistration $pending): void
    {
        $_SESSION['pending_registrations'][$pending->challenge] = $pending->userHandle;

        while (count($_SESSION['pending_registrations']) > self::MAX_PENDING) {
            array_shift($_SESSION['pending_registrations']);
        }
    }

    public function consumePendingRegistration(string $challenge): ?PendingRegistration
    {
        if (!array_key_exists($challenge, $_SESSION['pending_registrations'] ?? [])) {
            return null;
        }

        $userHandle = $_SESSION['pending_registrations'][$challenge];
        unset($_SESSION['pending_registrations'][$challenge]);

        return new PendingRegistration($challenge, $userHandle);
    }
}
