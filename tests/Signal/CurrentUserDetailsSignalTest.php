<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Signal;

use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Signal\CurrentUserDetailsSignal;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;
use function json_decode;
use const JSON_THROW_ON_ERROR;

class CurrentUserDetailsSignalTest extends WebAuthnTestCase
{

    public function testSerializesUserIdAsBase64urlAndDetailsVerbatim(): void
    {
        $signal = new CurrentUserDetailsSignal(
            rpId: 'example.com',
            userId: 'user-handle-bytes',
            name: 'alice@example.com',
            displayName: 'Alice Doe',
        );

        self::assertSame(
            [
                'rpId' => 'example.com',
                'userId' => Base64::urlEncode('user-handle-bytes'),
                'name' => 'alice@example.com',
                'displayName' => 'Alice Doe',
            ],
            json_decode($signal->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

}
