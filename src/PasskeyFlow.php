<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys;

use InvalidArgumentException;
use ShipMonk\Passkeys\Ceremony\AuthenticationExpectations;
use ShipMonk\Passkeys\Ceremony\AuthenticationResult;
use ShipMonk\Passkeys\Ceremony\CredentialRecord;
use ShipMonk\Passkeys\Ceremony\RegistrationExpectations;
use ShipMonk\Passkeys\Ceremony\RelyingParty;
use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Credential\MalformedDataException;
use ShipMonk\Passkeys\Credential\PublicKeyCredential;
use ShipMonk\Passkeys\Enum\AuthenticatorTransport;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialType;
use ShipMonk\Passkeys\Enum\ResidentKeyRequirement;
use ShipMonk\Passkeys\Enum\UserVerificationRequirement;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use ShipMonk\Passkeys\Options\AuthenticatorSelectionCriteria;
use ShipMonk\Passkeys\Options\PublicKeyCredentialCreationOptions;
use ShipMonk\Passkeys\Options\PublicKeyCredentialDescriptor;
use ShipMonk\Passkeys\Options\PublicKeyCredentialParameters;
use ShipMonk\Passkeys\Options\PublicKeyCredentialRequestOptions;
use ShipMonk\Passkeys\Options\PublicKeyCredentialRpEntity;
use ShipMonk\Passkeys\Options\PublicKeyCredentialUserEntity;
use ShipMonk\Passkeys\Signal\AllAcceptedCredentialsSignal;
use ShipMonk\Passkeys\Signal\CurrentUserDetailsSignal;
use function array_map;
use function hash_equals;
use function hash_hmac;
use function random_bytes;
use function strlen;

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
 *     rejected. An unknown username always leaves the ceremony unpinned; by default it also gets
 *     the usernameless empty `allowCredentials`, so a non-existent account and a known one without
 *     passkeys look alike — but a *known* account with passkeys still stands out through its
 *     non-empty list. Override {@see self::getEnumerationHardeningSecret()} to close that gap: a
 *     username with no passkeys is then served a stable fabricated descriptor indistinguishable
 *     from a real one, so every username yields the same response shape (the ceremony stays
 *     unpinned regardless; WebAuthn §14.6.2).
 *
 * Because both flows can run concurrently in one browser session (conditional mediation starts at
 * page load, a button click starts another ceremony), pending ceremonies are keyed by challenge:
 * {@see self::authenticate()} looks the ceremony up by the challenge inside the response instead
 * of assuming a single pending slot.
 *
 * Registration is the same pair of calls — {@see self::registrationOptions()} /
 * {@see self::register()} — for an account the caller has already resolved (the signed-in user
 * adding a passkey, or a just-created signup); pass `conditionalMediation: true` for the silent
 * passkey-upgrade variant offered right after a password login. Deciding *who* may enrol — verifying the email,
 * requiring an authenticated session — is deliberately left in front of the flow. Mind that a
 * pending registration stays completable for as long as the {@see PendingCeremonyStore} keeps it:
 * the enrolment authorization must still hold when {@see self::register()} is called, not just
 * when the options were issued, or a stale ceremony can attach a passkey to an account whose
 * ownership has since changed — pass the current account's handle as `$expectedUserHandle` to
 * have {@see self::register()} enforce exactly that.
 *
 * Policy knobs (user verification, algorithms, timeout…) are protected methods with defaults that
 * are right for passkeys; subclass only to override those.
 *
 * @api
 */
class PasskeyFlow
{

    /**
     * @param string       $rpId    the {@link https://w3c.github.io/webauthn/#rp-id RP ID} — the domain your passkeys are scoped to, e.g. `example.com` (it must be a registrable-suffix match of your origins)
     * @param string       $rpName  the human-readable relying party name, e.g. `Example Corp` — shown by authenticator UIs when a passkey is created
     * @param list<string> $origins the exact origins your login pages are served from, e.g. `['https://example.com']`
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

        // Username-enumeration hardening (WebAuthn §14.6.2): when a username was supplied but produced
        // no real descriptors — the account does not exist, or exists but has no passkeys — substitute
        // a stable, plausible fabricated descriptor so this response is indistinguishable from that of
        // an account that does have passkeys. A no-op unless getEnumerationHardeningSecret() is set;
        // it only shapes the response — verification (below, keyed by the pinned user handle) is
        // unchanged, so a ceremony for a non-existent account still fails closed.
        if ($username !== null && $allowCredentials === null) {
            $allowCredentials = $this->fabricateAllowCredentials($username);
        }

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
     * Set `$conditionalMediation` when the page will pass the options to
     * `navigator.credentials.create()` with `mediation: "conditional"` — the silent passkey
     * upgrade offered right after a password login. The client creates the passkey without any
     * user interaction (and only when its own conditions hold, e.g. the password was just
     * autofilled from its credential manager), so the response may carry neither the User Present
     * nor the User Verified flag: {@see self::register()} relaxes both checks for this ceremony,
     * and the options request `userVerification: "preferred"` instead of the configured policy —
     * a silent creation could never satisfy `required`. Everything the caller must guarantee for
     * a modal registration still applies, most notably that the account is authenticated.
     *
     * @param string      $userHandle           raw user handle bytes (an opaque, immutable, PII-free
     *      account id, at most 64 bytes — never the email itself; {@see self::generateUserHandle()}
     *      mints a spec-shaped one to store on the account)
     * @param string      $username             the human-readable account identifier (email/username),
     *        shown by authenticator UIs to label the passkey
     * @param string|null $displayName          a friendlier account label ("Alice Doe"), defaulting to the username
     * @param bool        $conditionalMediation whether the options are for a `mediation: "conditional"` creation
     */
    public function registrationOptions(
        string $userHandle,
        string $username,
        ?string $displayName = null,
        bool $conditionalMediation = false,
    ): PublicKeyCredentialCreationOptions
    {
        $challenge = $this->generateChallenge();
        $this->pendingCeremonyStore->rememberPendingRegistration(new PendingRegistration($challenge, $userHandle, $conditionalMediation));

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
                userVerification: $conditionalMediation
                    ? UserVerificationRequirement::PREFERRED
                    : $this->getUserVerificationRequirement(),
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
     * When the account the passkey may attach to is known at completion time — the usual case: the
     * signed-in user adding a passkey — pass its user handle as `$expectedUserHandle`. A pending
     * ceremony minted for any other account is then rejected *before* anything is verified or
     * persisted, so a ceremony started in user A's session can never complete in user B's and
     * attach a cross-user credential. Omit it only when the caller genuinely cannot know the
     * account yet (e.g. a passkey-first signup completing in a not-yet-authenticated session).
     *
     * @param string      $responseJson       raw request body containing the registration response JSON
     * @param string|null $expectedUserHandle raw user handle bytes of the account the completed ceremony
     *      must belong to, rejected with {@see VerificationException::USER_HANDLE_MISMATCH} otherwise
     *
     * @throws VerificationException
     */
    public function register(
        string $responseJson,
        ?string $expectedUserHandle = null,
    ): RegisteredPasskey
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

        if ($expectedUserHandle !== null && !hash_equals($expectedUserHandle, $pending->userHandle)) {
            throw new VerificationException(
                VerificationException::USER_HANDLE_MISMATCH,
                'Pending registration ceremony does not belong to the identified user',
            );
        }

        $result = $this->relyingParty->verifyRegistration(
            $credential,
            new RegistrationExpectations(
                challenge: $pending->challenge,
                rpId: $this->rpId,
                origins: $this->origins,
                allowedAlgorithms: $this->getAllowedAlgorithms(),
                // A conditional-mediation creation is silent, so neither flag can be demanded: the
                // expectations relax User Present (§7.1 step 15) via `conditionalMediation`, User
                // Verified must be relaxed here.
                requireUserVerification: !$pending->conditionalMediation
                    && $this->getUserVerificationRequirement() === UserVerificationRequirement::REQUIRED,
                allowCrossOrigin: $this->isCrossOriginAllowed(),
                allowedTopOrigins: $this->getAllowedTopOrigins(),
                conditionalMediation: $pending->conditionalMediation,
            ),
            $this->store,
        );

        $registered = new RegisteredPasskey($pending->userHandle, $credential->authenticatorAttachment, $result, $pending->conditionalMediation);
        $this->store->saveCredential($registered);

        return $registered;
    }

    /**
     * Mints a fresh user handle for a new account: 64 opaque, cryptographically random, PII-free
     * bytes — the spec-recommended choice, and one that satisfies WebAuthn §14.6.1 (the user handle
     * MUST NOT carry personally identifying information such as an email or username) by construction.
     *
     * The user handle is the account's WebAuthn identity: every passkey an account enrols shares one
     * immutable handle. So mint it once, when you create the account, store it there, and pass that
     * same value to {@see self::registrationOptions()} for every subsequent passkey — never generate
     * a fresh one per ceremony, or a second passkey would enrol under a different identity and fork
     * the account (breaking `excludeCredentials` de-duplication and login).
     *
     * @return string raw user handle bytes (64 bytes)
     */
    public function generateUserHandle(): string
    {
        return random_bytes(64);
    }

    // --- Signal API: keep credential providers in sync (WebAuthn §5.1.10) -----------------------

    /**
     * Builds the payload for `PublicKeyCredential.signalAllAcceptedCredentials()`: the *complete*
     * set of credential ids currently accepted for the account, for the browser to hand to the
     * credential provider so it prunes any passkey no longer on the list. Serialize it with
     * {@see AllAcceptedCredentialsSignal::toJson()} and pass it to the JS call.
     *
     * Call it after a successful sign-in (opportunistic re-sync) and whenever the account's
     * credential set changes — a passkey removed, or the account deleted, in which case the list is
     * legitimately empty and prunes them all. The list is drawn straight from the durable store, so
     * it stays authoritative: never hand the provider a filtered subset, or it hides the omitted —
     * still valid — passkeys.
     *
     * The matching `signalUnknownCredential()` call needs no server-built payload: the browser
     * already holds the credential id it just used and your RP ID, so it can prune a single
     * unrecognised credential itself once {@see self::authenticate()} rejects it with
     * {@see VerificationException::UNKNOWN_CREDENTIAL}.
     *
     * @param string $userHandle raw user handle bytes
     */
    public function allAcceptedCredentialsSignal(string $userHandle): AllAcceptedCredentialsSignal
    {
        $credentialIds = array_map(
            static fn (CredentialRecord $credential) => $credential->credentialId,
            $this->store->findCredentialsByUserHandle($userHandle),
        );

        return new AllAcceptedCredentialsSignal($this->rpId, $userHandle, $credentialIds);
    }

    /**
     * Builds the payload for `PublicKeyCredential.signalCurrentUserDetails()`: the account's current
     * `name` / `displayName`, for the browser to hand to the credential provider so the metadata it
     * shows for the account's passkeys stays current. Serialize it with
     * {@see CurrentUserDetailsSignal::toJson()} and pass it to the JS call.
     *
     * Call it after the user changes either value, and opportunistically after a successful sign-in.
     *
     * @param string $userHandle raw user handle bytes
     *
     * @throws InvalidArgumentException if the store has no account for the handle
     *      (its {@see PasskeyStore::findUserEntityByUserHandle()} returned null)
     */
    public function currentUserDetailsSignal(string $userHandle): CurrentUserDetailsSignal
    {
        $user = $this->store->findUserEntityByUserHandle($userHandle);

        if ($user === null) {
            throw new InvalidArgumentException('No account exists for the given user handle');
        }

        return new CurrentUserDetailsSignal($this->rpId, $user->id, $user->name, $user->displayName);
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

    /**
     * The secret that switches on username-enumeration hardening for the two-step flow (WebAuthn
     * §14.6.2). It defaults to null — the mitigation off — and then {@see self::authenticationOptions()}
     * leaves `allowCredentials` empty for a username with no passkeys, so an empty-vs-non-empty
     * response reveals which accounts have passkeys. Return a fixed, high-entropy secret (≥16 bytes,
     * e.g. 32 random bytes kept in app config — the *same* value on every request) and those
     * responses instead carry a plausible fabricated descriptor, so a probing attacker can no longer
     * tell passkey-bearing accounts from the rest.
     *
     * The secret MUST be stable across requests (a fresh one each time would make the fake
     * descriptors change between probes, exposing them as fake) and MUST stay secret (anyone who
     * knows it can recompute the fabricated ids and distinguish them from real ones). This equalizes
     * the *response*; a determined attacker may still find residual side channels (per-account
     * response timing, or the credential count) — override {@see self::fabricateAllowCredentials()}
     * if you need to narrow those too.
     *
     * @return string|null raw secret bytes, or null to disable the mitigation
     */
    protected function getEnumerationHardeningSecret(): ?string
    {
        return null;
    }

    /**
     * The fabricated `allowCredentials` served for a username that has no real credentials — the
     * §14.6.2 mitigation's decoy. The default derives one plausible descriptor deterministically from
     * the username with HMAC-SHA-256 keyed by {@see self::getEnumerationHardeningSecret()} (so it is
     * stable per username across probes yet unguessable without the secret), and returns null — the
     * mitigation off — when no secret is configured.
     *
     * Override to better match your real descriptors when the defaults are distinguishable from them
     * — e.g. a different credential-id length, transports, or more than one entry.
     *
     * @return list<PublicKeyCredentialDescriptor>|null
     *
     * @throws InvalidArgumentException if a configured secret is shorter than 16 bytes
     */
    protected function fabricateAllowCredentials(string $username): ?array
    {
        $secret = $this->getEnumerationHardeningSecret();

        if ($secret === null) {
            return null;
        }

        if (strlen($secret) < 16) {
            throw new InvalidArgumentException('The enumeration-hardening secret must be at least 16 bytes');
        }

        return [
            new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType::PUBLIC_KEY,
                hash_hmac('sha256', $username, $secret, binary: true),
                [AuthenticatorTransport::INTERNAL, AuthenticatorTransport::HYBRID],
            ),
        ];
    }

}
