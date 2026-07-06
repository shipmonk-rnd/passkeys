<?php declare(strict_types = 1);

namespace WebAuthnX\Passkey;

use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialRecord;
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
 * A high-level, passkey-only login flow on top of the {@see RelyingParty} façade: construct it
 * with your relying party identity and storage — a durable {@see PasskeyStore} and a
 * session-scoped {@see PendingCeremonyStore} — and wire the public methods to your HTTP
 * endpoints. It covers the two common ways passkey login is offered — usually both at once, on
 * the same page:
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
 * requiring an authenticated session — is deliberately left in front of the flow. Mind that a
 * pending registration stays completable for as long as the {@see PendingCeremonyStore} keeps it:
 * the enrolment authorization must still hold when {@see self::register()} is called, not just
 * when the options were issued, or a stale ceremony can attach a passkey to an account whose
 * ownership has since changed.
 *
 * Policy knobs (user verification, algorithms, timeout…) are protected methods with defaults that
 * are right for passkeys; subclass only to override those.
 *
 * @api
 */
class PasskeyFlow
{

    /**
     * @param string $rpId the {@link https://w3c.github.io/webauthn/#rp-id RP ID} — the
     *     domain your passkeys are scoped to, e.g. `example.com` (it must be a registrable-suffix
     *     match of your origins)
     * @param string $rpName the human-readable relying party name, e.g. `Example Corp` —
     *     shown by authenticator UIs when a passkey is created
     * @param list<string> $origins the exact origins your login pages are served from,
     *     e.g. `['https://example.com']`
     */
    public function __construct(
        private readonly string $rpId,
        private readonly string $rpName,
        private readonly array $origins,
        private readonly PasskeyStore $store,
        private readonly PendingCeremonyStore $pendingCeremonyStore,
        private readonly RelyingParty $relyingParty = new RelyingParty(),
    )
    {
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
        $userHandle = $username === null ? null : $this->store->findUserHandleByUsername($username);
        $allowCredentials = $userHandle === null ? null : $this->credentialDescriptorsFor($userHandle);
        $challenge = $this->generateChallenge();
        $this->pendingCeremonyStore->rememberPendingAuthentication(new PendingAuthentication($challenge, $userHandle));

        return new PublicKeyCredentialRequestOptions(
            challenge: $challenge,
            timeout: $this->getTimeout(),
            rpId: $this->rpId,
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
     *
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
        $pending = $this->pendingCeremonyStore->consumePendingAuthentication($clientData->getChallenge());

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
            $this->store->findCredentialsByUserHandle($pending->userHandle),
        );

        $result = $this->relyingParty->verifyAuthentication(
            $credential,
            new AuthenticationExpectations(
                challenge: $pending->challenge,
                rpId: $this->rpId,
                origins: $this->origins,
                allowedCredentialIds: $allowedCredentialIds,
                requireUserVerification: $this->getUserVerificationRequirement() === UserVerificationRequirement::REQUIRED,
                allowCrossOrigin: $this->isCrossOriginAllowed(),
                allowedTopOrigins: $this->getAllowedTopOrigins(),
                expectedUserHandle: $pending->userHandle,
            ),
            $this->store,
        );

        $this->store->updateCredential($result);

        return $result;
    }

    /**
     * Starts a registration ceremony for an account the caller has already resolved and is
     * entitled to enrol for: issues a challenge, records the pending ceremony via
     * {@see self::rememberPendingRegistration()}, and returns the options to hand to the
     * browser's `navigator.credentials.create()`. Credentials the account already has are listed
     * in `excludeCredentials` so the same authenticator cannot enrol twice.
     *
     * @param string $userHandle raw user handle bytes (an opaque, immutable, PII-free
     *     account id, at most 64 bytes — never the email itself)
     * @param string $username the human-readable account identifier (email/username),
     *     shown by authenticator UIs to label the passkey
     * @param string|null $displayName a friendlier account label ("Alice Doe"), defaulting to the username
     */
    public function registrationOptions(
        string $userHandle,
        string $username,
        ?string $displayName = null,
    ): PublicKeyCredentialCreationOptions
    {
        $challenge = $this->generateChallenge();
        $this->pendingCeremonyStore->rememberPendingRegistration(new PendingRegistration($challenge, $userHandle));

        return new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(name: $this->rpName, id: $this->rpId),
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
     *
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

        $pending = $this->pendingCeremonyStore->consumePendingRegistration($clientData->getChallenge());

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
                rpId: $this->rpId,
                origins: $this->origins,
                allowedAlgorithms: $this->getAllowedAlgorithms(),
                requireUserVerification: $this->getUserVerificationRequirement() === UserVerificationRequirement::REQUIRED,
                allowCrossOrigin: $this->isCrossOriginAllowed(),
                allowedTopOrigins: $this->getAllowedTopOrigins(),
            ),
            $this->store,
        );

        $registered = new RegisteredPasskey($pending->userHandle, $credential->authenticatorAttachment, $result);
        $this->store->saveCredential($registered);

        return $registered;
    }

    /**
     * The account's registered credentials as descriptors for `allowCredentials` /
     * `excludeCredentials`, or null (omit the member) when it has none.
     *
     * @param string $userHandle raw user handle bytes
     * @return list<PublicKeyCredentialDescriptor>|null
     */
    private function credentialDescriptorsFor(string $userHandle): ?array
    {
        $credentials = $this->store->findCredentialsByUserHandle($userHandle);

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

    // --- Policy defaults: sensible for passkeys, override to taste ------------------------------

    /**
     * How much the ceremony must prove about the human ({@see UserVerificationRequirement}).
     * Defaults to `required` — a passkey then carries both factors (possession + PIN/biometric).
     * Override to `preferred` for maximal authenticator compatibility (e.g. security keys without
     * a PIN), trading away the second factor.
     */
    protected function getUserVerificationRequirement(): UserVerificationRequirement
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
     */
    protected function getResidentKeyRequirement(): ResidentKeyRequirement
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
