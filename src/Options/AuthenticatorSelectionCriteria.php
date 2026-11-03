<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Enum\AuthenticatorAttachment;
use ShipMonk\Passkeys\Enum\ResidentKeyRequirement;
use ShipMonk\Passkeys\Enum\UserVerificationRequirement;
use stdClass;

/**
 * @see https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria
 * @api
 */
final class AuthenticatorSelectionCriteria implements JsonSerializable
{

    public function __construct(
        public readonly ?AuthenticatorAttachment $authenticatorAttachment = null,
        public readonly ?ResidentKeyRequirement $residentKey = null,
        public readonly ?bool $requireResidentKey = null,
        public readonly ?UserVerificationRequirement $userVerification = null,
    )
    {
    }

    /**
     * @return stdClass&object{
     *     authenticatorAttachment?: AuthenticatorAttachment,
     *     residentKey?: ResidentKeyRequirement,
     *     requireResidentKey?: bool,
     *     userVerification?: UserVerificationRequirement,
     * }
     */
    public function jsonSerialize(): stdClass
    {
        $data = [];

        if ($this->authenticatorAttachment !== null) {
            $data['authenticatorAttachment'] = $this->authenticatorAttachment;
        }

        if ($this->residentKey !== null) {
            $data['residentKey'] = $this->residentKey;
        }

        if ($this->requireResidentKey !== null) {
            $data['requireResidentKey'] = $this->requireResidentKey;
        }

        if ($this->userVerification !== null) {
            $data['userVerification'] = $this->userVerification;
        }

        return (object) $data;
    }

}
