<?php declare(strict_types = 1);

namespace WebAuthnX\Enum;

/**
 * @api
 */
class PublicKeyCredentialHints
{
	final public const string SECURITY_KEY = 'security-key';
	final public const string CLIENT_DEVICE = 'client-device';
	final public const string HYBRID = 'hybrid';
}
