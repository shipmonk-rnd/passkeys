<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Options;

use PHPUnit\Framework\Attributes\CoversClass;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Enum\AuthenticatorTransport;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialHint;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialType;
use ShipMonk\Passkeys\Enum\UserVerificationRequirement;
use ShipMonk\Passkeys\Options\PublicKeyCredentialDescriptor;
use ShipMonk\Passkeys\Options\PublicKeyCredentialRequestOptions;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_decode;
use const JSON_THROW_ON_ERROR;

#[CoversClass(PublicKeyCredentialRequestOptions::class)]
final class PublicKeyCredentialRequestOptionsTest extends PasskeysTestCase
{

    public function testSerializesAllMembers(): void
    {
        $options = new PublicKeyCredentialRequestOptions(
            challenge: 'challenge-bytes',
            timeout: 60_000,
            rpId: 'example.com',
            allowCredentials: [
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType::PUBLIC_KEY,
                    'cred-1',
                    [AuthenticatorTransport::USB],
                ),
            ],
            userVerification: UserVerificationRequirement::PREFERRED,
            hints: [PublicKeyCredentialHint::SECURITY_KEY],
            extensions: ['appid' => 'https://example.com/appid.json'],
        );

        self::assertSame(
            [
                'challenge' => Base64::urlEncode('challenge-bytes'),
                'timeout' => 60_000,
                'rpId' => 'example.com',
                'allowCredentials' => [
                    [
                        'type' => 'public-key',
                        'id' => Base64::urlEncode('cred-1'),
                        'transports' => ['usb'],
                    ],
                ],
                'userVerification' => 'preferred',
                'hints' => ['security-key'],
                'extensions' => ['appid' => 'https://example.com/appid.json'],
            ],
            json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testSerializesOnlyRequiredMembersWithRecommendedTimeoutDefault(): void
    {
        $options = new PublicKeyCredentialRequestOptions(
            challenge: 'challenge-bytes',
        );

        self::assertSame(
            [
                'challenge' => Base64::urlEncode('challenge-bytes'),
                'timeout' => PublicKeyCredentialRequestOptions::RECOMMENDED_TIMEOUT,
            ],
            json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testNullTimeoutIsOmitted(): void
    {
        $options = new PublicKeyCredentialRequestOptions(
            challenge: 'challenge-bytes',
            timeout: null,
        );

        self::assertSame(
            ['challenge' => Base64::urlEncode('challenge-bytes')],
            json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testEmptyExtensionsSerializeAsJsonObject(): void
    {
        $options = new PublicKeyCredentialRequestOptions(
            challenge: 'challenge-bytes',
            extensions: [],
        );

        self::assertStringContainsString('"extensions":{}', $options->toJson());
    }

}
