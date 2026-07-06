<?php declare(strict_types = 1);

namespace WebAuthnX\Passkey;

use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\CredentialStore;
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Credential\MalformedDataException;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Enum\PublicKeyCredentialType;
use WebAuthnX\Enum\ResidentKeyRequirement;
use WebAuthnX\Enum\UserVerificationRequirement;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;
use WebAuthnX\Options\AuthenticatorSelectionCriteria;
use WebAuthnX\Options\PublicKeyCredentialCreationOptions;
use WebAuthnX\Options\PublicKeyCredentialDescriptor;
use WebAuthnX\Options\PublicKeyCredentialParameters;
use WebAuthnX\Options\PublicKeyCredentialRequestOptions;
use WebAuthnX\Options\PublicKeyCredentialRpEntity;
use WebAuthnX\Options\PublicKeyCredentialUserEntity;
use WebAuthnX\RelyingParty;

use function array_map;
use function random_bytes;

/**
 * A high-level, passkey-only login flow on top of the {@see RelyingParty} façade: extend it,
 * implement the abstract lookups and state hooks against your own storage, and wire the two
 * public methods to two HTTP endpoints. It covers the two common ways passkey login is offered —
 * usually both at once, on the same page:
 *
 *  1. A dedicated "sign in with a passkey" button (and/or conditional-mediation autofill), where
 *     no username is known: call {@see self::authenticationOptions()} with null. The options carry
 *     no `allowCredentials`; a discoverable credential identifies the user via its user handle.
 *  2. A two-step login form (username/email first, password or passkey second): pass the entered
 *     username. If the account is known, the options list its credentials in `allowCredentials`
 *     and the ceremony is pinned to that account — an assertion by any other user's credential is
 *     rejected. An unknown username silently falls back to the usernameless options above, so the
 *     response does not by itself confirm whether an account exists (note that a *known* account's
 *     non-empty `allowCredentials` still reveals that it has passkeys; if that distinction matters
 *     to you, respond with fabricated descriptors yourself instead of calling this method).
 *
 * Because both flows can run concurrently in one browser session (conditional mediation starts at
 * page load, a button click starts another ceremony), pending ceremonies are keyed by challenge:
 * {@see self::authenticate()} looks the ceremony up by the challenge inside the response instead
 * of assuming a single pending slot.
 *
 * Registration is the same pair of calls — {@see self::registrationOptions()} /
 * {@see self::register()} — for an account the caller has already resolved (the signed-in user
 * adding a passkey, or a just-created signup). Deciding *who* may enrol — verifying the email,
 * requiring an authenticated session — is deliberately left in front of the flow.
 *
 * @api
 */
abstract class PasskeyFlow implements CredentialStore
{
	public function __construct(
		private readonly RelyingParty $relyingParty = new RelyingParty(),
	) {
	}

	// --- The flow: wire these two methods to your endpoints -------------------------------------

	/**
	 * Starts an authentication ceremony: issues a challenge, records the pending ceremony via
	 * {@see self::rememberPendingAuthentication()}, and returns the options to hand to the
	 * browser's `navigator.credentials.get()` (see {@see PublicKeyCredentialRequestOptions::toJson()}).
	 *
	 * @param string|null $username how the login form identified the account (email/username),
	 *     or null for the dedicated-button / conditional-mediation flow
	 */
	public function authenticationOptions(?string $username = null): PublicKeyCredentialRequestOptions
	{
		$userHandle = $username === null ? null : $this->findUserHandleByUsername($username);
		$allowCredentials = $userHandle === null ? null : $this->credentialDescriptorsFor($userHandle);
		$challenge = $this->generateChallenge();
		$this->rememberPendingAuthentication(new PendingAuthentication($challenge, $userHandle));

		return new PublicKeyCredentialRequestOptions(
			challenge: $challenge,
			timeout: $this->getTimeout(),
			rpId: $this->getRelyingPartyId(),
			allowCredentials: $allowCredentials,
			userVerification: $this->getUserVerificationRequirement(),
		);
	}

	/**
	 * Finishes an authentication ceremony: parses the JSON the browser produced (the
	 * `PublicKeyCredential.toJSON()` output posted by your page), locates the pending ceremony by
	 * the challenge inside the response, runs the full WebAuthn §7.2 verification, and persists
	 * the outcome via {@see self::updateCredential()}.
	 *
	 * On success the returned result identifies the authenticated user
	 * ({@see AuthenticationResult::$userHandle}); establishing their session is the caller's job.
	 * Anything else — malformed input, an unknown or already-used challenge, a failed check —
	 * throws, so a passkey login endpoint reduces to one call and one catch.
	 *
	 * @param string $responseJson raw request body containing the authentication response JSON
	 * @throws VerificationException
	 */
	public function authenticate(string $responseJson): AuthenticationResult
	{
		try {
			$credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString($responseJson));
			$clientData = $credential->response->parseClientData();

		} catch (JsonObjectException | MalformedDataException $e) {
			throw new VerificationException(
				VerificationException::MALFORMED_RESPONSE,
				'Malformed authentication response: ' . $e->getMessage(),
				$e,
			);
		}

		// The challenge is the ceremony key; it is attacker-supplied until verifyAuthentication()
		// re-checks it (in constant time) against the pending record consumed here.
		$pending = $this->consumePendingAuthentication($clientData->getChallenge());

		if ($pending === null) {
			throw new VerificationException(
				VerificationException::CHALLENGE_MISMATCH,
				'No pending authentication ceremony matches the challenge — it may have expired or been used already',
			);
		}

		// For a pinned ceremony the allow-list is re-read from storage rather than persisted in the
		// pending state; the user-handle pin is what actually ties the assertion to the account.
		$allowedCredentialIds = $pending->userHandle === null ? null : array_map(
			static fn (CredentialRecord $credential) => $credential->credentialId,
			$this->findCredentialsByUserHandle($pending->userHandle),
		);

		$result = $this->relyingParty->verifyAuthentication(
			$credential,
			new AuthenticationExpectations(
				challenge: $pending->challenge,
				rpId: $this->getRelyingPartyId(),
				origins: $this->getAllowedOrigins(),
				allowedCredentialIds: $allowedCredentialIds,
				requireUserVerification: $this->getUserVerificationRequirement() === UserVerificationRequirement::REQUIRED,
				allowCrossOrigin: $this->isCrossOriginAllowed(),
				allowedTopOrigins: $this->getAllowedTopOrigins(),
				expectedUserHandle: $pending->userHandle,
			),
			$this,
		);

		$this->updateCredential($result);

		return $result;
	}

	/**
	 * Starts a registration ceremony for an account the caller has already resolved and is
	 * entitled to enrol for: issues a challenge, records the pending ceremony via
	 * {@see self::rememberPendingRegistration()}, and returns the options to hand to the
	 * browser's `navigator.credentials.create()`. Credentials the account already has are listed
	 * in `excludeCredentials` so the same authenticator cannot enrol twice.
	 *
	 * @param string      $userHandle  raw user handle bytes (an opaque, immutable, PII-free
	 *     account id, at most 64 bytes — never the email itself)
	 * @param string      $username    the human-readable account identifier (email/username),
	 *     shown by authenticator UIs to label the passkey
	 * @param string|null $displayName a friendlier account label ("Alice Doe"), defaulting to the username
	 */
	public function registrationOptions(
		string $userHandle,
		string $username,
		?string $displayName = null,
	): PublicKeyCredentialCreationOptions {
		$challenge = $this->generateChallenge();
		$this->rememberPendingRegistration(new PendingRegistration($challenge, $userHandle));

		return new PublicKeyCredentialCreationOptions(
			rp: new PublicKeyCredentialRpEntity(name: $this->getRelyingPartyName(), id: $this->getRelyingPartyId()),
			user: new PublicKeyCredentialUserEntity(id: $userHandle, name: $username, displayName: $displayName ?? $username),
			challenge: $challenge,
			pubKeyCredParams: array_map(
				static fn (int $algorithm) => new PublicKeyCredentialParameters(PublicKeyCredentialType::PUBLIC_KEY, $algorithm),
				$this->getAllowedAlgorithms(),
			),
			timeout: $this->getTimeout(),
			excludeCredentials: $this->credentialDescriptorsFor($userHandle),
			authenticatorSelection: new AuthenticatorSelectionCriteria(
				residentKey: $this->getResidentKeyRequirement(),
				userVerification: $this->getUserVerificationRequirement(),
			),
		);
	}

	/**
	 * Finishes a registration ceremony: parses the JSON the browser produced, locates the pending
	 * ceremony by the challenge inside the response, runs the full WebAuthn §7.1 verification, and
	 * persists the new credential via {@see self::saveCredential()}.
	 *
	 * The returned {@see RegisteredPasskey} identifies the enrolled account (e.g. to sign the user
	 * in after a passkey-first signup); failures throw, exactly as in {@see self::authenticate()}.
	 *
	 * @param string $responseJson raw request body containing the registration response JSON
	 * @throws VerificationException
	 */
	public function register(string $responseJson): RegisteredPasskey
	{
		try {
			$credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString($responseJson));
			$clientData = $credential->response->parseClientData();

		} catch (JsonObjectException | MalformedDataException $e) {
			throw new VerificationException(
				VerificationException::MALFORMED_RESPONSE,
				'Malformed registration response: ' . $e->getMessage(),
				$e,
			);
		}

		$pending = $this->consumePendingRegistration($clientData->getChallenge());

		if ($pending === null) {
			throw new VerificationException(
				VerificationException::CHALLENGE_MISMATCH,
				'No pending registration ceremony matches the challenge — it may have expired or been used already',
			);
		}

		$result = $this->relyingParty->verifyRegistration(
			$credential,
			new RegistrationExpectations(
				challenge: $pending->challenge,
				rpId: $this->getRelyingPartyId(),
				origins: $this->getAllowedOrigins(),
				allowedAlgorithms: $this->getAllowedAlgorithms(),
				requireUserVerification: $this->getUserVerificationRequirement() === UserVerificationRequirement::REQUIRED,
				allowCrossOrigin: $this->isCrossOriginAllowed(),
				allowedTopOrigins: $this->getAllowedTopOrigins(),
			),
			$this,
		);

		$registered = new RegisteredPasskey($pending->userHandle, $credential->authenticatorAttachment, $result);
		$this->saveCredential($registered);

		return $registered;
	}

	/**
	 * The account's registered credentials as descriptors for `allowCredentials` /
	 * `excludeCredentials`, or null (omit the member) when it has none.
	 *
	 * @param  string $userHandle raw user handle bytes
	 * @return list<PublicKeyCredentialDescriptor>|null
	 */
	private function credentialDescriptorsFor(string $userHandle): ?array
	{
		$credentials = $this->findCredentialsByUserHandle($userHandle);

		if ($credentials === []) {
			return null;
		}

		return array_map(
			static fn (CredentialRecord $credential) => new PublicKeyCredentialDescriptor(
				PublicKeyCredentialType::PUBLIC_KEY,
				$credential->credentialId,
				$credential->transports,
			),
			$credentials,
		);
	}

	// --- Identity of the relying party: every deployment must define these ----------------------

	/**
	 * The {@link https://w3c.github.io/webauthn/#rp-id RP ID} — the domain your passkeys are
	 * scoped to, e.g. `example.com` (it must be a registrable-suffix match of your origins).
	 */
	abstract protected function getRelyingPartyId(): string;

	/**
	 * The human-readable relying party name, e.g. `Example Corp` — shown by authenticator UIs
	 * when a passkey is created.
	 */
	abstract protected function getRelyingPartyName(): string;

	/**
	 * The exact origins your login pages are served from, e.g. `['https://example.com']`.
	 *
	 * @return list<string>
	 */
	abstract protected function getAllowedOrigins(): array;

	// --- Storage lookups: implement against your user / credential tables -----------------------

	/**
	 * Maps a login-form identifier (email/username) to the account's user handle, or null when no
	 * such account exists. Only consulted for the two-step flow.
	 *
	 * @return string|null raw user handle bytes
	 */
	abstract protected function findUserHandleByUsername(string $username): ?string;

	/**
	 * Every credential registered to the given account — used to build `allowCredentials` /
	 * `excludeCredentials` and to enforce the former at verification.
	 *
	 * @param  string $userHandle raw user handle bytes
	 * @return list<CredentialRecord>
	 */
	abstract protected function findCredentialsByUserHandle(string $userHandle): array;

	// --- Ceremony state: implement on top of your session / cache -------------------------------

	/**
	 * Stores a pending ceremony, keyed by its challenge (encode {@see PendingAuthentication::$challenge}
	 * before using it as an array/cache key — it is raw bytes). Scope the storage to the browser
	 * session, and bound it: cap the number of concurrently pending ceremonies (a handful is
	 * plenty) or expire them, since a page may start several without finishing any.
	 */
	abstract protected function rememberPendingAuthentication(PendingAuthentication $pending): void;

	/**
	 * Returns **and deletes** the pending ceremony stored under this challenge, or null when
	 * there is none. The deletion is what makes each challenge single-use — the anti-replay
	 * control.
	 *
	 * The challenge comes out of the (yet unverified) response, so treat it as untrusted input:
	 * look it up, never evaluate it.
	 *
	 * @param string $challenge raw challenge bytes
	 */
	abstract protected function consumePendingAuthentication(string $challenge): ?PendingAuthentication;

	/**
	 * The registration counterpart of {@see self::rememberPendingAuthentication()} — same keying
	 * and bounding advice, but keep the two stores separate so a response can never finish a
	 * ceremony of the other kind.
	 */
	abstract protected function rememberPendingRegistration(PendingRegistration $pending): void;

	/**
	 * Returns **and deletes** the pending registration ceremony stored under this challenge, or
	 * null when there is none; see {@see self::consumePendingAuthentication()}.
	 *
	 * @param string $challenge raw challenge bytes
	 */
	abstract protected function consumePendingRegistration(string $challenge): ?PendingRegistration;

	/**
	 * Persists the newly registered credential — typically one INSERT of
	 * {@see RegisteredPasskey::toCredentialRecord()}, plus whatever extra columns you keep
	 * ({@see RegisteredPasskey::$authenticatorAttachment}, a created-at timestamp, a label…).
	 */
	abstract protected function saveCredential(RegisteredPasskey $passkey): void;

	/**
	 * Persists the post-authentication credential state: set the record's `signCount` to
	 * {@see AuthenticationResult::$newSignCount}, `backupState` to {@see AuthenticationResult::$backupState},
	 * and — if it was not already — `uvInitialized` to {@see AuthenticationResult::$userVerified}.
	 * This is also the place to react to {@see AuthenticationResult::$possibleClone} if you want to.
	 */
	abstract protected function updateCredential(AuthenticationResult $result): void;

	// --- Policy defaults: sensible for passkeys, override to taste ------------------------------

	/**
	 * How much the ceremony must prove about the human ({@see UserVerificationRequirement}).
	 * Defaults to `required` — a passkey then carries both factors (possession + PIN/biometric).
	 * Override to `preferred` for maximal authenticator compatibility (e.g. security keys without
	 * a PIN), trading away the second factor.
	 *
	 * @return UserVerificationRequirement::*
	 */
	protected function getUserVerificationRequirement(): string
	{
		return UserVerificationRequirement::REQUIRED;
	}

	/**
	 * The COSE algorithms offered at registration, best first, and enforced on the attested key
	 * (WebAuthn §7.1 step 20). The default triple covers what real-world authenticators produce.
	 *
	 * @return non-empty-list<CoseAlgorithmIdentifier::*>
	 */
	protected function getAllowedAlgorithms(): array
	{
		return [
			CoseAlgorithmIdentifier::ES256,
			CoseAlgorithmIdentifier::RS256,
			CoseAlgorithmIdentifier::EdDSA,
		];
	}

	/**
	 * Whether new credentials must be discoverable (client-side). Defaults to `required` — that
	 * is what makes the credential a passkey, and what the usernameless flow depends on.
	 *
	 * @return ResidentKeyRequirement::*
	 */
	protected function getResidentKeyRequirement(): string
	{
		return ResidentKeyRequirement::REQUIRED;
	}

	/**
	 * The ceremony timeout in milliseconds sent to the client (a hint; clients ignore it for
	 * conditional mediation), or null to omit it. Defaults to the spec-recommended 300 s.
	 */
	protected function getTimeout(): ?int
	{
		return PublicKeyCredentialRequestOptions::RECOMMENDED_TIMEOUT;
	}

	/**
	 * Whether an assertion made in a cross-origin iframe is acceptable. When enabling this, also
	 * override {@see self::getAllowedTopOrigins()}.
	 */
	protected function isCrossOriginAllowed(): bool
	{
		return false;
	}

	/**
	 * The exact top-level origins allowed to embed your login page in an iframe. Only consulted
	 * when {@see self::isCrossOriginAllowed()} returns true and the client reports a top origin.
	 *
	 * @return list<string>
	 */
	protected function getAllowedTopOrigins(): array
	{
		return [];
	}

	/**
	 * Generates the per-ceremony challenge. The default 32 random bytes are right for nearly
	 * everyone; an override must return at least 16 bytes (WebAuthn §13.4.3) of fresh
	 * cryptographic randomness.
	 *
	 * @return string raw challenge bytes
	 */
	protected function generateChallenge(): string
	{
		return random_bytes(32);
	}
}
