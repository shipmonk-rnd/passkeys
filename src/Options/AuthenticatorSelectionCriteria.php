<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Enum\AuthenticatorAttachment;
use ShipMonk\Passkeys\Enum\ResidentKeyRequirement;
use ShipMonk\Passkeys\Enum\UserVerificationRequirement;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria
 * @api
 */
readonly class AuthenticatorSelectionCriteria implements JsonSerializable
{

    public function __construct(
        public ?AuthenticatorAttachment $authenticatorAttachment = null,
        public ?ResidentKeyRequirement $residentKey = null,
        public ?bool $requireResidentKey = null,
        public ?UserVerificationRequirement $userVerification = null,
    )
    {
    }

    /**
     * @return array{
     *     authenticatorAttachment?: AuthenticatorAttachment,
     *     residentKey?: ResidentKeyRequirement,
     *     requireResidentKey?: bool,
     *     userVerification?: UserVerificationRequirement,
     * }
     */
    public function jsonSerialize(): array
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

        return $data;
    }

}
