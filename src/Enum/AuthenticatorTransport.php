<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Enum;

/**
 * @api
 */
final class AuthenticatorTransport
{

    public const string USB = 'usb';
    public const string NFC = 'nfc';
    public const string BLE = 'ble';
    public const string SMART_CARD = 'smart-card';
    public const string HYBRID = 'hybrid';
    public const string INTERNAL = 'internal';

}
