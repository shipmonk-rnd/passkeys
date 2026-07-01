<?php declare(strict_types = 1);

namespace WebAuthnX;

use JsonSerializable;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
 */
readonly class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity implements JsonSerializable
{
	public function __construct(
		public string $id,
		string $name,
	) {
		parent::__construct($name);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		return [
			'id' => $this->id,
			'name' => $this->name,
		];
	}
}
