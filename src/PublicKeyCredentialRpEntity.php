<?php declare(strict_types = 1);

namespace WebAuthnX;

readonly class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity
{
	public function __construct(
		public string $id,
		string $name,
	) {
		parent::__construct($name);
	}
}
