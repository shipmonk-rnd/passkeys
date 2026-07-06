<?php declare(strict_types = 1);

namespace WebAuthnXTests\Options;

use InvalidArgumentException;
use WebAuthnX\Enum\AuthenticatorAttachment;
use WebAuthnX\Options\AuthenticatorSelectionCriteria;
use WebAuthnX\Enum\AuthenticatorTransport;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Options\PublicKeyCredentialCreationOptions;
use WebAuthnX\Options\PublicKeyCredentialDescriptor;
use WebAuthnX\Enum\PublicKeyCredentialHint;
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Enum\PublicKeyCredentialType;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;
use WebAuthnX\Enum\ResidentKeyRequirement;
use WebAuthnX\Enum\UserVerificationRequirement;
use WebAuthnXTests\WebAuthnTestCase;

use function json_decode;
use function str_repeat;
use function strlen;

use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialCreationOptionsTest extends WebAuthnTestCase
{
    public function testSerializesAllMembers(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'Alice Smith'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::RS256),
            ],
            timeout: 60000,
            excludeCredentials: [
                new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType::PUBLIC_KEY,
                    'cred-1',
                    [AuthenticatorTransport::INTERNAL, AuthenticatorTransport::HYBRID],
                ),
            ],
            authenticatorSelection: new AuthenticatorSelectionCriteria(
                authenticatorAttachment: AuthenticatorAttachment::PLATFORM,
                residentKey: ResidentKeyRequirement::REQUIRED,
                requireResidentKey: true,
                userVerification: UserVerificationRequirement::REQUIRED,
            ),
            hints: [PublicKeyCredentialHint::CLIENT_DEVICE],
            extensions: ['credProps' => true],
        );

        self::assertSame(
            [
                'rp' => ['name' => 'Example RP', 'id' => 'example.com'],
                'user' => [
                    'id' => Base64::urlEncode('user-id'),
                    'name' => 'alice',
                    'displayName' => 'Alice Smith',
                ],
                'challenge' => Base64::urlEncode('challenge-bytes'),
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::ES256],
                    ['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::RS256],
                ],
                'timeout' => 60000,
                'excludeCredentials' => [
                    [
                        'type' => 'public-key',
                        'id' => Base64::urlEncode('cred-1'),
                        'transports' => ['internal', 'hybrid'],
                    ],
                ],
                'authenticatorSelection' => [
                    'authenticatorAttachment' => 'platform',
                    'residentKey' => 'required',
                    'requireResidentKey' => true,
                    'userVerification' => 'required',
                ],
                'hints' => ['client-device'],
                'extensions' => ['credProps' => true],
            ],
            json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testSerializesOnlyRequiredMembersWithRecommendedTimeoutDefault(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'Alice Smith'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
            ],
        );

        self::assertSame(
            [
                'rp' => ['name' => 'Example RP', 'id' => 'example.com'],
                'user' => [
                    'id' => Base64::urlEncode('user-id'),
                    'name' => 'alice',
                    'displayName' => 'Alice Smith',
                ],
                'challenge' => Base64::urlEncode('challenge-bytes'),
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::ES256],
                ],
                'timeout' => PublicKeyCredentialCreationOptions::RECOMMENDED_TIMEOUT,
            ],
            json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
        );
    }

    public function testNullTimeoutIsOmitted(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'Alice Smith'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
            ],
            timeout: null,
        );

        $decoded = json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertArrayNotHasKey('timeout', $decoded);
    }

    public function testEmptyExtensionsSerializeAsJsonObject(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'Alice Smith'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
            ],
            extensions: [],
        );

        self::assertStringContainsString('"extensions":{}', $options->toJson());
    }

    public function testRpEntityOmitsIdWhenNull(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'Alice Smith'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
            ],
        );

        $decoded = json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertSame(['name' => 'Example RP'], $decoded['rp'] ?? null);
    }

    /**
     * User-controlled text (name/displayName) must not be able to break out of an HTML <script>
     * block: json_encode's default slash-escaping turns "</script>" into "<\/script>", which the
     * HTML script-data end-tag scanner does not match. Guards against re-adding JSON_UNESCAPED_SLASHES.
     */
    public function testUserTextIsScriptSafe(): void
    {
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: 'Example RP'),
            user: new PublicKeyCredentialUserEntity('user-id', 'alice', 'a</script>b'),
            challenge: 'challenge-bytes',
            pubKeyCredParams: [
                new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
            ],
        );

        $json = $options->toJson();
        self::assertStringNotContainsString('</script>', $json);
        self::assertStringContainsString('a<\/script>b', $json);
    }

    public function testUserEntityRejectsEmptyUserHandle(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('User handle must be 1 to 64 bytes');

        new PublicKeyCredentialUserEntity('', 'alice', 'Alice Smith');
    }

    public function testUserEntityRejectsOverlongUserHandle(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('User handle must be 1 to 64 bytes');

        new PublicKeyCredentialUserEntity(str_repeat('a', 65), 'alice', 'Alice Smith');
    }

    public function testUserEntityAcceptsBoundaryUserHandles(): void
    {
        self::assertSame('a', (new PublicKeyCredentialUserEntity('a', 'alice', 'Alice Smith'))->id);
        self::assertSame(64, strlen((new PublicKeyCredentialUserEntity(str_repeat('a', 64), 'alice', 'Alice Smith'))->id));
    }

    public function testDescriptorOmitsTransportsWhenNull(): void
    {
        $descriptor = new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType::PUBLIC_KEY,
            'cred-1',
        );

        self::assertSame(
            ['type' => 'public-key', 'id' => Base64::urlEncode('cred-1')],
            $descriptor->jsonSerialize(),
        );
    }
}
