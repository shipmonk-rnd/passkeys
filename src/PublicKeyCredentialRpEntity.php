<?php declare(strict_types = 1);

namespace WebAuthnX;

use JsonSerializable;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
 */
readonly class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity implements JsonSerializable
{
	/**
	 * `$id` is optional: when null it is omitted from the serialized options and the browser
	 * defaults the RP ID to the caller's effective domain.
	 */
	public function __construct(
		string $name,
		public ?string $id = null,
	) {
		parent::__construct($name);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$data = ['name' => $this->name];

		if ($this->id !== null) {
			$data['id'] = $this->id;
		}

		return $data;
	}
}
