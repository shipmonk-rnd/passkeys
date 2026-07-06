<?php declare(strict_types = 1);

namespace WebAuthnX\Enum;

/**
 * @api
 */
class UserVerificationRequirement
{
	final public const string DISCOURAGED = 'discouraged';
	final public const string PREFERRED = 'preferred';
	final public const string REQUIRED = 'required';
}
