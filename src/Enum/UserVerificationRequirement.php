<?php declare(strict_types = 1);

namespace WebAuthnX\Enum;

class UserVerificationRequirement
{
	final public const DISCOURAGED = 'discouraged';
	final public const PREFERRED = 'preferred';
	final public const REQUIRED = 'required';
}
