<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

/**
 * @api
 */
readonly abstract class PublicKeyCredentialEntity
{
	public function __construct(
		public string $name,
	) {
	}
}
