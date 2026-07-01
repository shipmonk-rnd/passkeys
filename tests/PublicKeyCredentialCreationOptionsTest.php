<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use WebAuthnX\AuthenticatorAttachment;
use WebAuthnX\AuthenticatorSelectionCriteria;
use WebAuthnX\AuthenticatorTransport;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\PublicKeyCredentialCreationOptions;
use WebAuthnX\PublicKeyCredentialDescriptor;
use WebAuthnX\PublicKeyCredentialHints;
use WebAuthnX\PublicKeyCredentialParameters;
use WebAuthnX\PublicKeyCredentialRpEntity;
use WebAuthnX\PublicKeyCredentialType;
use WebAuthnX\PublicKeyCredentialUserEntity;
use WebAuthnX\ResidentKeyRequirement;
use WebAuthnX\UserVerificationRequirement;

use function json_decode;

use const JSON_THROW_ON_ERROR;

class PublicKeyCredentialCreationOptionsTest extends WebAuthnTestCase
{
	public function testSerializesAllMembers(): void
	{
		$options = new PublicKeyCredentialCreationOptions(
			rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
			user: new PublicKeyCredentialUserEntity(Bytes::fromBinaryString('user-id'), 'alice', 'Alice Smith'),
			challenge: Bytes::fromBinaryString('challenge-bytes'),
			pubKeyCredParams: [
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::RS256),
			],
			timeout: 60000,
			excludeCredentials: [
				new PublicKeyCredentialDescriptor(
					PublicKeyCredentialType::PUBLIC_KEY,
					Bytes::fromBinaryString('cred-1'),
					[AuthenticatorTransport::INTERNAL, AuthenticatorTransport::HYBRID],
				),
			],
			authenticatorSelection: new AuthenticatorSelectionCriteria(
				authenticatorAttachment: AuthenticatorAttachment::PLATFORM,
				residentKey: ResidentKeyRequirement::REQUIRED,
				requireResidentKey: true,
				userVerification: UserVerificationRequirement::REQUIRED,
			),
			hints: [PublicKeyCredentialHints::CLIENT_DEVICE],
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
			],
			json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
		);
	}

	public function testSerializesOnlyRequiredMembers(): void
	{
		$options = new PublicKeyCredentialCreationOptions(
			rp: new PublicKeyCredentialRpEntity(name: 'Example RP', id: 'example.com'),
			user: new PublicKeyCredentialUserEntity(Bytes::fromBinaryString('user-id'), 'alice', 'Alice Smith'),
			challenge: Bytes::fromBinaryString('challenge-bytes'),
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
			],
			json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR),
		);
	}

	public function testRpEntityOmitsIdWhenNull(): void
	{
		$options = new PublicKeyCredentialCreationOptions(
			rp: new PublicKeyCredentialRpEntity(name: 'Example RP'),
			user: new PublicKeyCredentialUserEntity(Bytes::fromBinaryString('user-id'), 'alice', 'Alice Smith'),
			challenge: Bytes::fromBinaryString('challenge-bytes'),
			pubKeyCredParams: [
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
			],
		);

		$decoded = json_decode($options->toJson(), true, flags: JSON_THROW_ON_ERROR);
		self::assertIsArray($decoded);
		self::assertSame(['name' => 'Example RP'], $decoded['rp']);
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
			user: new PublicKeyCredentialUserEntity(Bytes::fromBinaryString('user-id'), 'alice', 'a</script>b'),
			challenge: Bytes::fromBinaryString('challenge-bytes'),
			pubKeyCredParams: [
				new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, CoseAlgorithmIdentifier::ES256),
			],
		);

		$json = $options->toJson();
		self::assertStringNotContainsString('</script>', $json);
		self::assertStringContainsString('a<\/script>b', $json);
	}

	public function testDescriptorOmitsTransportsWhenNull(): void
	{
		$descriptor = new PublicKeyCredentialDescriptor(
			PublicKeyCredentialType::PUBLIC_KEY,
			Bytes::fromBinaryString('cred-1'),
		);

		self::assertSame(
			['type' => 'public-key', 'id' => Base64::urlEncode('cred-1')],
			$descriptor->jsonSerialize(),
		);
	}
}
