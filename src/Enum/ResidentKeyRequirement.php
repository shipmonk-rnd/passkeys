<?php declare(strict_types = 1);

namespace WebAuthnX\Enum;

/**
 * @api
 */
class ResidentKeyRequirement
{
	final public const DISCOURAGED = 'discouraged';
	final public const PREFERRED = 'preferred';
	final public const REQUIRED = 'required';
}
