<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Passkey;

use ShipMonk\Passkeys\Ceremony\CredentialRecord;
use ShipMonk\Passkeys\Ceremony\RegistrationResult;
use ShipMonk\Passkeys\Enum\AuthenticatorAttachment;

/**
 * The outcome of a successful {@see PasskeyFlow::register()}: the verified ceremony result
 * together with the flow-level context it lacks — whose account the passkey now belongs to and,
 * when the client reported it, how the authenticator was attached (useful for labelling the
 * passkey in account settings).
 *
 * By the time this object is handed to {@see PasskeyFlow::saveCredential()} / returned to the
 * caller, every WebAuthn §7.1 check has passed; {@see self::toCredentialRecord()} assembles the
 * record to persist.
 *
 * @api
 */
final readonly class RegisteredPasskey
{

    /**
     * @param string                       $userHandle              raw user handle bytes of the account the passkey was registered to
     * @param AuthenticatorAttachment|null $authenticatorAttachment the client-asserted attachment, null when the client sent none or an unknown value — a display hint, not a trusted value
     * @param bool                         $conditionalMediation    whether the passkey came from a conditional-mediation (silent passkey-upgrade) ceremony — e.g. to notify the user that a passkey was created for them
     */
    public function __construct(
        public string $userHandle,
        public ?AuthenticatorAttachment $authenticatorAttachment,
        public RegistrationResult $result,
        public bool $conditionalMediation = false,
    )
    {
    }

    public function toCredentialRecord(): CredentialRecord
    {
        return $this->result->toCredentialRecord($this->userHandle);
    }

}
