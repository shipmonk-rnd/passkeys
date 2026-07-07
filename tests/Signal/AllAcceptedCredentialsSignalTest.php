<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Signal;

use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Signal\AllAcceptedCredentialsSignal;
use ShipMonk\WebAuthnTests\WebAuthnTestCase;
use function json_decode;
use const JSON_THROW_ON_ERROR;

class AllAcceptedCredentialsSignalTest extends WebAuthnTestCase
{

    public function testSerializesRawBytesAsBase64url(): void
    {
        $signal = new AllAcceptedCredentialsSignal(
            rpId: 'example.com',
            userId: 'user-handle-bytes',
            allAcceptedCredentialIds: ['cred-1', 'cred-2'],
        );

        self::assertSame(
            [
                'rpId' => 'example.com',
                'userId' => Base64::urlEncode('user-handle-bytes'),
                'allAcceptedCredentialIds' => [
                    Base64::urlEncode('cred-1'),
                    Base64::urlEncode('cred-2'),
                ],
            ],
            json_decode($signal->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testEmptyListSerializesAsEmptyJsonArray(): void
    {
        $signal = new AllAcceptedCredentialsSignal(
            rpId: 'example.com',
            userId: 'user-handle-bytes',
            allAcceptedCredentialIds: [],
        );

        self::assertStringContainsString('"allAcceptedCredentialIds":[]', $signal->toJson());
    }

}
