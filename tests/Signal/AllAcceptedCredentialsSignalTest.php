<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Signal;

use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Signal\AllAcceptedCredentialsSignal;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_decode;
use const JSON_THROW_ON_ERROR;

final class AllAcceptedCredentialsSignalTest extends PasskeysTestCase
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
