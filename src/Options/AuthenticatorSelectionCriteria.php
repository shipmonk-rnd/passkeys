<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Enum\AuthenticatorAttachment;
use WebAuthnX\Enum\ResidentKeyRequirement;
use WebAuthnX\Enum\UserVerificationRequirement;

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
	) {
	}

	/**
	 * @return array<string, mixed>
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
