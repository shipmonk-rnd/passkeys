<?php declare(strict_types = 1);

namespace WebAuthnX;

readonly class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity
{
	public function __construct(
		public string $id,
		string $name,
		public string $displayName,
	) {
		parent::__construct($name);
	}
}
