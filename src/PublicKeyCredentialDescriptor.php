<?php declare(strict_types = 1);

namespace WebAuthnX;

use JsonSerializable;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;

/**
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialdescriptorjson
 */
readonly class PublicKeyCredentialDescriptor implements JsonSerializable
{
	/**
	 * @param  PublicKeyCredentialType::*           $type
	 * @param  list<AuthenticatorTransport::*>|null $transports
	 */
	public function __construct(
		public string $type,
		public Bytes $id,
		public ?array $transports = null,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$data = [
			'type' => $this->type,
			'id' => Base64::urlEncode($this->id->toBinaryString()),
		];

		if ($this->transports !== null) {
			$data['transports'] = $this->transports;
		}

		return $data;
	}
}
