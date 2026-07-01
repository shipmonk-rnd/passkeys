<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\AuthenticatorTransport;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\PublicKeyCredentialDescriptor;
use WebAuthnX\PublicKeyCredentialHints;
use WebAuthnX\PublicKeyCredentialRequestOptions;
use WebAuthnX\PublicKeyCredentialType;
use WebAuthnX\UserVerificationRequirement;

use function json_decode;

use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialRequestOptionsTest extends WebAuthnTestCase
{
	public function testSerializesAllMembers(): void
	{
		$options = new PublicKeyCredentialRequestOptions(
			challenge: Bytes::fromBinaryString('challenge-bytes'),
			timeout: 60000,
			rpId: 'example.com',
			allowCredentials: [
				new PublicKeyCredentialDescriptor(
					PublicKeyCredentialType::PUBLIC_KEY,
					Bytes::fromBinaryString('cred-1'),
					[AuthenticatorTransport::USB],
				),
			],
			userVerification: UserVerificationRequirement::PREFERRED,
			hints: [PublicKeyCredentialHints::SECURITY_KEY],
		);

		self::assertSame(
			[
				'challenge' => Base64::urlEncode('challenge-bytes'),
				'timeout' => 60000,
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
			],
			json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
		);
	}

	public function testSerializesOnlyRequiredMembers(): void
	{
		$options = new PublicKeyCredentialRequestOptions(
			challenge: Bytes::fromBinaryString('challenge-bytes'),
		);

		self::assertSame(
			['challenge' => Base64::urlEncode('challenge-bytes')],
			json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
		);
	}
}
