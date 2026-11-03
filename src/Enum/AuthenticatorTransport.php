<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Enum;

/**
 * @api
 */
final class AuthenticatorTransport
{

    public const USB = 'usb';
    public const NFC = 'nfc';
    public const BLE = 'ble';
    public const SMART_CARD = 'smart-card';
    public const HYBRID = 'hybrid';
    public const INTERNAL = 'internal';

}
