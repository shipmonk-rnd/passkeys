<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys;

/**
 * The server-side state of one authentication ceremony started by
 * {@see PasskeyFlow::authenticationOptions()} and finished by {@see PasskeyFlow::authenticate()}:
 * the issued challenge and — when the user identified themselves first (two-step login) — the
 * user handle the assertion must belong to.
 *
 * The flow keys pending ceremonies by their challenge, so several may exist at once per browser
 * session.
 *
 * @api
 */
final readonly class PendingAuthentication
{

    /**
     * @param string      $challenge  raw challenge bytes issued for this ceremony
     * @param string|null $userHandle raw user handle bytes when the ceremony is pinned to an already-identified user; null for a usernameless (discoverable-credential) ceremony
     */
    public function __construct(
        public string $challenge,
        public ?string $userHandle,
    )
    {
    }

}
