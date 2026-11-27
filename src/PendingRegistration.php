<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys;

/**
 * The server-side state of one registration ceremony started by
 * {@see PasskeyFlow::registrationOptions()} and finished by {@see PasskeyFlow::register()}: the
 * issued challenge and the user the new passkey will belong to.
 *
 * Like authentication ceremonies, these are keyed by challenge — but stored separately, so a
 * response can never finish a ceremony of the other kind.
 *
 * @api
 */
final readonly class PendingRegistration
{

    /**
     * @param string $challenge            raw challenge bytes issued for this ceremony
     * @param string $userHandle           raw user handle bytes of the account being enrolled
     * @param bool   $conditionalMediation whether the options were issued for a conditional-mediation
     *      (silent passkey-upgrade) creation, which relaxes the User Present and User Verified
     *      checks when {@see PasskeyFlow::register()} finishes this ceremony
     */
    public function __construct(
        public string $challenge,
        public string $userHandle,
        public bool $conditionalMediation,
    )
    {
    }

}
