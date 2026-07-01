<?php declare(strict_types = 1);

namespace WebAuthnXDemo;

use RuntimeException;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Credential\AttestationObject;

use function base64_decode;
use function base64_encode;
use function file_get_contents;
use function file_put_contents;
use function is_dir;
use function json_decode;
use function json_encode;
use function mkdir;
use function rtrim;
use function strtr;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * A tiny file-backed store for the demo. NOT production code — a real relying party would use a
 * database, one row per credential, and proper session handling for the pending challenge.
 *
 * It illustrates one non-obvious point about integrating the library: {@see CredentialRecord}
 * carries a live {@see \WebAuthnX\Cose\CoseKey}, and the library ships no way to serialise that key
 * on its own. So to persist a credential we keep the raw `attestationObject` the browser sent at
 * registration (base64url) and re-parse it back into a CoseKey whenever the record is loaded.
 */
final class PasskeyStore implements CredentialStore
{
	private string $file;

	/** @var array{challenge?: string, user?: array{handle: string, name: string}, credentials: array<string, array{attestationObject: string, signCount: int, userHandle: string, uvInitialized: bool, backupEligible: bool, backupState: bool, transports: list<string>|null}>} */
	private array $data;

	public function __construct(string $dir)
	{
		if (!is_dir($dir)) {
			mkdir($dir, 0777, recursive: true);
		}

		$this->file = $dir . '/store.json';
		$raw = @file_get_contents($this->file);
		$this->data = $raw === false
			? ['credentials' => []]
			: json_decode($raw, associative: true, flags: JSON_THROW_ON_ERROR);
	}

	public function findByCredentialId(Bytes $credentialId): ?CredentialRecord
	{
		$key = self::b64UrlEncode($credentialId->toBinaryString());
		$record = $this->data['credentials'][$key] ?? null;

		if ($record === null) {
			return null;
		}

		return new CredentialRecord(
			credentialId: $credentialId,
			publicKey: $this->rehydratePublicKey($record['attestationObject']),
			signCount: $record['signCount'],
			userHandle: Bytes::fromBinaryString(self::b64UrlDecode($record['userHandle'])),
			uvInitialized: $record['uvInitialized'],
			backupEligible: $record['backupEligible'],
			backupState: $record['backupState'],
			transports: $record['transports'],
		);
	}

	/**
	 * Persists a freshly registered credential. The library-supplied {@see CredentialRecord} holds
	 * everything except a serialisable public key, so we additionally keep the raw attestation
	 * object the browser sent and re-derive the key from it on later logins.
	 */
	public function save(CredentialRecord $record, Bytes $attestationObject): void
	{
		$this->data['credentials'][self::b64UrlEncode($record->credentialId->toBinaryString())] = [
			'attestationObject' => self::b64UrlEncode($attestationObject->toBinaryString()),
			'signCount' => $record->signCount,
			'userHandle' => self::b64UrlEncode($record->userHandle->toBinaryString()),
			'uvInitialized' => $record->uvInitialized,
			'backupEligible' => $record->backupEligible,
			'backupState' => $record->backupState,
			'transports' => $record->transports,
		];
		$this->flush();
	}

	public function updateSignCount(Bytes $credentialId, int $newSignCount): void
	{
		$key = self::b64UrlEncode($credentialId->toBinaryString());

		if (isset($this->data['credentials'][$key])) {
			$this->data['credentials'][$key]['signCount'] = $newSignCount;
			$this->flush();
		}
	}

	/** The single demo user; created on first registration. */
	public function user(): ?array
	{
		return $this->data['user'] ?? null;
	}

	public function setUser(Bytes $handle, string $name): void
	{
		$this->data['user'] = ['handle' => self::b64UrlEncode($handle->toBinaryString()), 'name' => $name];
		$this->flush();
	}

	public function userNameForHandle(Bytes $handle): ?string
	{
		$user = $this->data['user'] ?? null;

		return $user !== null && $user['handle'] === self::b64UrlEncode($handle->toBinaryString())
			? $user['name']
			: null;
	}

	/** Stores the pending ceremony challenge server-side (a real RP would key this per session). */
	public function rememberChallenge(Bytes $challenge): void
	{
		$this->data['challenge'] = self::b64UrlEncode($challenge->toBinaryString());
		$this->flush();
	}

	/** Returns and clears the pending challenge, so each challenge is single-use. */
	public function consumeChallenge(): ?Bytes
	{
		$challenge = $this->data['challenge'] ?? null;
		unset($this->data['challenge']);
		$this->flush();

		return $challenge === null ? null : Bytes::fromBinaryString(self::b64UrlDecode($challenge));
	}

	private function rehydratePublicKey(string $attestationObjectB64): CoseKey
	{
		$attestationObject = Bytes::fromBinaryString(self::b64UrlDecode($attestationObjectB64));
		$parsed = BytesReader::read(
			$attestationObject,
			static fn (BytesReader $reader): AttestationObject => AttestationObject::fromCborMap(CborMap::fromBytesReader($reader)),
		);

		$attestedCredentialData = $parsed->parseAuthenticatorData()->attestedCredentialData;

		if ($attestedCredentialData === null) {
			throw new RuntimeException('Stored attestation object has no attested credential data');
		}

		return $attestedCredentialData->credentialPublicKey;
	}

	private function flush(): void
	{
		file_put_contents($this->file, json_encode($this->data, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
	}

	public static function b64UrlEncode(string $binary): string
	{
		return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
	}

	public static function b64UrlDecode(string $text): string
	{
		return base64_decode(strtr($text, '-_', '+/'));
	}
}
