<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Signal;

use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Signal\CurrentUserDetailsSignal;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_decode;
use const JSON_THROW_ON_ERROR;

class CurrentUserDetailsSignalTest extends PasskeysTestCase
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
