<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Enum;

/**
 * @api
 */
class AuthenticatorTransport
{

    final public const string USB = 'usb';
    final public const string NFC = 'nfc';
    final public const string BLE = 'ble';
    final public const string SMART_CARD = 'smart-card';
    final public const string HYBRID = 'hybrid';
    final public const string INTERNAL = 'internal';

}
