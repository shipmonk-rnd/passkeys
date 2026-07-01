<?php declare(strict_types = 1);

namespace WebAuthnX\Enum;

class AuthenticatorTransport
{
	final public const USB = 'usb';
	final public const NFC = 'nfc';
	final public const BLE = 'ble';
	final public const SMART_CARD = 'smart-card';
	final public const HYBRID = 'hybrid';
	final public const INTERNAL = 'internal';
}
