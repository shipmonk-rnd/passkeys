<?php declare(strict_types = 1);

namespace WebAuthnX;

readonly class PublicKeyCredentialDescriptor
{
	/**
	 * @param  PublicKeyCredentialType::*           $type
	 * @param  list<AuthenticatorTransport::*>|null $transports
	 */
	public function __construct(
		public string $type,
		public string $id,
		public ?array $transports = null
	) {
	}
}
