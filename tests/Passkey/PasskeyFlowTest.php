<?php declare(strict_types = 1);

namespace ShipMonk\WebAuthnTests\Passkey;

use OpenSSLAsymmetricKey;
use ShipMonk\WebAuthn\Base64\Base64;
use ShipMonk\WebAuthn\Ceremony\CredentialRecord;
use ShipMonk\WebAuthn\Ceremony\VerificationException;
use ShipMonk\WebAuthn\Cose\CoseAlgorithmIdentifier;
use ShipMonk\WebAuthn\Cose\CoseKey;
use ShipMonk\WebAuthn\Credential\AuthenticatorData;
use ShipMonk\WebAuthn\Enum\AuthenticatorAttachment;
use ShipMonk\WebAuthn\Enum\ResidentKeyRequirement;
use ShipMonk\WebAuthn\Enum\UserVerificationRequirement;
use ShipMonk\WebAuthn\Options\PublicKeyCredentialParameters;
use ShipMonk\WebAuthn\Options\PublicKeyCredentialRequestOptions;
use ShipMonk\WebAuthn\Passkey\PasskeyFlow;
use ShipMonk\WebAuthn\Passkey\PasskeyStore;
use ShipMonk\WebAuthn\Passkey\PendingCeremonyStore;
use ShipMonk\WebAuthnTests\Cbor\CborTestEncoder;
use ShipMonk\WebAuthnTests\CryptoTestCase;
use function array_map;
use function base64_encode;
use function chr;
use function hash;
use function json_encode;
use function ord;
use function pack;
use function strlen;
use const JSON_THROW_ON_ERROR;

/**
 * Exercises {@see PasskeyFlow} against in-memory stores ({@see InMemoryPasskeyStore},
 * {@see InMemoryPendingCeremonyStore}), covering both entry flows — usernameless (dedicated
 * button / conditional mediation) and two-step (username first) — plus the challenge-keyed
 * pending-ceremony state that lets them run concurrently.
 *
 * The §7.2 checks themselves are covered by {@see RelyingPartyTest}; here only a representative
 * failure per layer asserts that the flow wires expectations and state correctly.
 */
class PasskeyFlowTest extends CryptoTestCase
{

    private const string RP_ID = 'example.com';
    private const string ORIGIN = 'https://example.com';

    private const string ALICE = 'alice@example.com';
    private const string ALICE_HANDLE = 'alice-handle-0001';
    private const string ALICE_CREDENTIAL_ID = "\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a";
    private const string BOB_HANDLE = 'bob-handle-000002';
    private const string BOB_CREDENTIAL_ID = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    private const string DAVE = 'dave@example.com';
    private const string DAVE_HANDLE = 'dave-handle-00004';
    private const string NEW_CREDENTIAL_ID = "\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d";
    private const string AAGUID = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

    private const int FLAGS_UP_UV = AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_USER_VERIFIED;

    /**
     * @var array<int, int|string>
     */
    private array $coseEntries;

    private OpenSSLAsymmetricKey $privateKey;

    private InMemoryPasskeyStore $store;

    private InMemoryPendingCeremonyStore $pending;

    protected function setUp(): void
    {
        [$this->privateKey, $this->coseEntries] = self::generateKeyAndCoseEntries(CoseAlgorithmIdentifier::ES256);
        $this->store = new InMemoryPasskeyStore();
        $this->pending = new InMemoryPendingCeremonyStore();
    }

    // --- Flow 1: usernameless (dedicated button / conditional mediation) ------------------------

    public function testUsernamelessRoundTrip(): void
    {
        $flow = $this->flowWithAlice();

        $options = $flow->authenticationOptions();

        self::assertSame(32, strlen($options->challenge));
        self::assertSame(self::RP_ID, $options->rpId);
        self::assertNull($options->allowCredentials);
        self::assertSame(UserVerificationRequirement::REQUIRED, $options->userVerification);
        self::assertSame(PublicKeyCredentialRequestOptions::RECOMMENDED_TIMEOUT, $options->timeout);

        $pending = $this->pending->pendingAuthentications[base64_encode($options->challenge)] ?? null;
        self::assertNotNull($pending);
        self::assertNull($pending->userHandle);

        $result = $flow->authenticate($this->aliceAssertion($options->challenge, signCount: 7));

        self::assertSame(self::ALICE_HANDLE, $result->userHandle);
        self::assertSame(self::ALICE_CREDENTIAL_ID, $result->credentialId);
        self::assertSame(7, $result->newSignCount);
        self::assertSame([$result], $this->store->updatedCredentials);
        self::assertSame([], $this->pending->pendingAuthentications);
    }

    public function testReplayedResponseIsRejected(): void
    {
        $flow = $this->flowWithAlice();
        $body = $this->aliceAssertion($flow->authenticationOptions()->challenge);

        $flow->authenticate($body);

        $this->assertAuthenticationFails(VerificationException::CHALLENGE_MISMATCH, $flow, $body);
        self::assertCount(1, $this->store->updatedCredentials);
    }

    // --- Flow 2: two-step (username first) -------------------------------------------------------

    public function testTwoStepRoundTripPinsIdentifiedUser(): void
    {
        $flow = $this->flowWithAlice();

        $options = $flow->authenticationOptions(self::ALICE);

        self::assertNotNull($options->allowCredentials);
        self::assertCount(1, $options->allowCredentials);
        self::assertSame(self::ALICE_CREDENTIAL_ID, $options->allowCredentials[0]->id);
        self::assertSame(['internal', 'hybrid'], $options->allowCredentials[0]->transports);
        self::assertSame(self::ALICE_HANDLE, $this->pending->pendingAuthentications[base64_encode($options->challenge)]->userHandle ?? null);

        $result = $flow->authenticate($this->aliceAssertion($options->challenge));

        self::assertSame(self::ALICE_HANDLE, $result->userHandle);
    }

    public function testTwoStepRejectsAnotherUsersCredential(): void
    {
        $flow = $this->flowWithAlice();
        [$bobKey, $bobCoseEntries] = self::generateKeyAndCoseEntries(CoseAlgorithmIdentifier::ES256);
        $this->store->addUser('bob@example.com', self::BOB_HANDLE);
        $this->store->addCredential($this->record(self::BOB_CREDENTIAL_ID, self::BOB_HANDLE, $bobCoseEntries));

        $options = $flow->authenticationOptions(self::ALICE);

        $this->assertAuthenticationFails(
            VerificationException::CREDENTIAL_NOT_ALLOWED,
            $flow,
            self::assertionBody($bobKey, $options->challenge, self::BOB_CREDENTIAL_ID, self::BOB_HANDLE),
        );
    }

    public function testUnknownUsernameFallsBackToUsernamelessOptions(): void
    {
        $flow = $this->flowWithAlice();

        $options = $flow->authenticationOptions('nobody@example.com');

        self::assertNull($options->allowCredentials);
        $pending = $this->pending->pendingAuthentications[base64_encode($options->challenge)] ?? null;
        self::assertNotNull($pending);
        self::assertNull($pending->userHandle);

        // A discoverable passkey of an existing account still signs in.
        $result = $flow->authenticate($this->aliceAssertion($options->challenge));
        self::assertSame(self::ALICE_HANDLE, $result->userHandle);
    }

    public function testKnownUserWithoutPasskeysStaysPinned(): void
    {
        $flow = $this->flowWithAlice();
        $this->store->addUser('carol@example.com', 'carol-handle-0003');

        $options = $flow->authenticationOptions('carol@example.com');

        // Nothing to allow-list, but the ceremony still belongs to carol: alice's passkey must not pass.
        self::assertNull($options->allowCredentials);
        $this->assertAuthenticationFails(
            VerificationException::USER_HANDLE_MISMATCH,
            $flow,
            $this->aliceAssertion($options->challenge),
        );
    }

    // --- Combined flows: challenge-keyed pending ceremonies -------------------------------------

    public function testConcurrentCeremoniesAreKeyedByChallenge(): void
    {
        $flow = $this->flowWithAlice();

        // Page load starts a conditional-mediation ceremony, the login form a pinned one.
        $conditionalOptions = $flow->authenticationOptions();
        $twoStepOptions = $flow->authenticationOptions(self::ALICE);
        self::assertCount(2, $this->pending->pendingAuthentications);

        // Answering the earlier ceremony works and leaves the later one intact, and vice versa.
        $flow->authenticate($this->aliceAssertion($conditionalOptions->challenge));
        self::assertCount(1, $this->pending->pendingAuthentications);

        $flow->authenticate($this->aliceAssertion($twoStepOptions->challenge, signCount: 2));
        self::assertSame([], $this->pending->pendingAuthentications);
        self::assertCount(2, $this->store->updatedCredentials);
    }

    // --- Registration -----------------------------------------------------------------------------

    public function testRegistrationThenLoginRoundTrip(): void
    {
        $flow = $this->createFlow();

        $options = $flow->registrationOptions(self::DAVE_HANDLE, self::DAVE);

        self::assertSame('Example RP', $options->rp->name);
        self::assertSame(self::RP_ID, $options->rp->id);
        self::assertSame(self::DAVE_HANDLE, $options->user->id);
        self::assertSame(self::DAVE, $options->user->name);
        self::assertSame(self::DAVE, $options->user->displayName);
        self::assertSame(
            [CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256, CoseAlgorithmIdentifier::EdDSA],
            array_map(static fn (PublicKeyCredentialParameters $parameters) => $parameters->alg, $options->pubKeyCredParams),
        );
        self::assertSame(ResidentKeyRequirement::REQUIRED, $options->authenticatorSelection?->residentKey);
        self::assertSame(UserVerificationRequirement::REQUIRED, $options->authenticatorSelection->userVerification);
        self::assertNull($options->excludeCredentials);
        self::assertSame(32, strlen($options->challenge));

        $pending = $this->pending->pendingRegistrations[base64_encode($options->challenge)] ?? null;
        self::assertNotNull($pending);
        self::assertSame(self::DAVE_HANDLE, $pending->userHandle);

        $registered = $flow->register($this->registrationBody($options->challenge));

        self::assertSame(self::DAVE_HANDLE, $registered->userHandle);
        self::assertSame(AuthenticatorAttachment::PLATFORM, $registered->authenticatorAttachment);
        self::assertSame(self::NEW_CREDENTIAL_ID, $registered->result->credentialId);
        self::assertSame(['internal'], $registered->toCredentialRecord()->transports);
        self::assertSame([$registered], $this->store->savedPasskeys);
        self::assertSame([], $this->pending->pendingRegistrations);

        // The passkey saved by the flow immediately works for a usernameless login.
        $loginOptions = $flow->authenticationOptions();
        $result = $flow->authenticate(self::assertionBody(
            $this->privateKey,
            $loginOptions->challenge,
            self::NEW_CREDENTIAL_ID,
            self::DAVE_HANDLE,
        ));
        self::assertSame(self::DAVE_HANDLE, $result->userHandle);
    }

    public function testRegistrationOptionsExcludeExistingCredentials(): void
    {
        $flow = $this->flowWithAlice();

        $options = $flow->registrationOptions(self::ALICE_HANDLE, self::ALICE);

        self::assertNotNull($options->excludeCredentials);
        self::assertCount(1, $options->excludeCredentials);
        self::assertSame(self::ALICE_CREDENTIAL_ID, $options->excludeCredentials[0]->id);
        self::assertSame(['internal', 'hybrid'], $options->excludeCredentials[0]->transports);
    }

    public function testReplayedRegistrationResponseIsRejected(): void
    {
        $flow = $this->createFlow();
        $body = $this->registrationBody($flow->registrationOptions(self::DAVE_HANDLE, self::DAVE)->challenge);

        $flow->register($body);

        $this->assertRegistrationFails(VerificationException::CHALLENGE_MISMATCH, $flow, $body);
        self::assertCount(1, $this->store->savedPasskeys);
    }

    public function testRegistrationRejectsDisallowedAlgorithm(): void
    {
        $flow = $this->createFlow();
        [, $es384CoseEntries] = self::generateKeyAndCoseEntries(CoseAlgorithmIdentifier::ES384);

        $options = $flow->registrationOptions(self::DAVE_HANDLE, self::DAVE);

        $this->assertRegistrationFails(
            VerificationException::UNSUPPORTED_ALGORITHM,
            $flow,
            $this->registrationBody($options->challenge, coseEntries: $es384CoseEntries),
        );
        self::assertSame([], $this->store->savedPasskeys);
    }

    public function testMalformedRegistrationResponseIsRejected(): void
    {
        $flow = $this->createFlow();

        $this->assertRegistrationFails(VerificationException::MALFORMED_RESPONSE, $flow, 'not json');
        $this->assertRegistrationFails(VerificationException::MALFORMED_RESPONSE, $flow, '{}');
    }

    public function testPendingRegistrationsAndAuthenticationsAreSeparate(): void
    {
        $flow = $this->flowWithAlice();
        $authenticationChallenge = $flow->authenticationOptions()->challenge;
        $registrationChallenge = $flow->registrationOptions(self::DAVE_HANDLE, self::DAVE)->challenge;

        // A response of one kind cannot consume — or even burn — a ceremony of the other kind.
        $this->assertRegistrationFails(
            VerificationException::CHALLENGE_MISMATCH,
            $flow,
            $this->registrationBody($authenticationChallenge),
        );
        $this->assertAuthenticationFails(
            VerificationException::CHALLENGE_MISMATCH,
            $flow,
            $this->aliceAssertion($registrationChallenge),
        );
        self::assertCount(1, $this->pending->pendingAuthentications);
        self::assertCount(1, $this->pending->pendingRegistrations);
    }

    // --- Failure wiring ---------------------------------------------------------------------------

    public function testUnknownChallengeIsRejected(): void
    {
        $flow = $this->flowWithAlice();

        $this->assertAuthenticationFails(
            VerificationException::CHALLENGE_MISMATCH,
            $flow,
            $this->aliceAssertion('never-issued-challenge-32-bytes!'),
        );
    }

    public function testMalformedResponseIsRejected(): void
    {
        $flow = $this->flowWithAlice();
        $flow->authenticationOptions();

        $this->assertAuthenticationFails(VerificationException::MALFORMED_RESPONSE, $flow, 'not json');
        $this->assertAuthenticationFails(VerificationException::MALFORMED_RESPONSE, $flow, '{}');

        // A response that never parsed must not consume the pending ceremony.
        self::assertCount(1, $this->pending->pendingAuthentications);
    }

    public function testFailedVerificationDoesNotUpdateCredential(): void
    {
        $flow = $this->flowWithAlice();
        $options = $flow->authenticationOptions();

        $this->assertAuthenticationFails(
            VerificationException::INVALID_SIGNATURE,
            $flow,
            $this->aliceAssertion($options->challenge, tamperSignature: true),
        );
        self::assertSame([], $this->store->updatedCredentials);
    }

    // --- Policy defaults and overrides -----------------------------------------------------------

    public function testUserVerificationIsRequiredByDefault(): void
    {
        $flow = $this->flowWithAlice();
        $options = $flow->authenticationOptions();

        $this->assertAuthenticationFails(
            VerificationException::USER_NOT_VERIFIED,
            $flow,
            $this->aliceAssertion($options->challenge, flags: AuthenticatorData::FLAG_USER_PRESENT),
        );
    }

    public function testUserVerificationOverrideAcceptsUnverifiedAssertion(): void
    {
        $flow = $this->flowWithAlice(userVerification: UserVerificationRequirement::PREFERRED);
        $options = $flow->authenticationOptions();

        self::assertSame(UserVerificationRequirement::PREFERRED, $options->userVerification);

        $result = $flow->authenticate(
            $this->aliceAssertion($options->challenge, flags: AuthenticatorData::FLAG_USER_PRESENT),
        );
        self::assertFalse($result->userVerified);
    }

    public function testCrossOriginIsRejectedByDefault(): void
    {
        $flow = $this->flowWithAlice();
        $options = $flow->authenticationOptions();

        $this->assertAuthenticationFails(
            VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
            $flow,
            $this->aliceAssertion($options->challenge, crossOrigin: true),
        );
    }

    public function testCrossOriginOverrideAcceptsCrossOriginAssertion(): void
    {
        $flow = $this->flowWithAlice(crossOriginAllowed: true);
        $options = $flow->authenticationOptions();

        $result = $flow->authenticate($this->aliceAssertion($options->challenge, crossOrigin: true));
        self::assertSame(self::ALICE_HANDLE, $result->userHandle);
    }

    // --- Assertion helpers ------------------------------------------------------------------------

    private function assertAuthenticationFails(
        string $reason,
        PasskeyFlow $flow,
        string $body,
    ): void
    {
        try {
            $flow->authenticate($body);
            self::fail('Expected authentication to fail with ' . $reason);

        } catch (VerificationException $e) {
            self::assertSame($reason, $e->reason);
        }
    }

    private function assertRegistrationFails(
        string $reason,
        PasskeyFlow $flow,
        string $body,
    ): void
    {
        try {
            $flow->register($body);
            self::fail('Expected registration to fail with ' . $reason);

        } catch (VerificationException $e) {
            self::assertSame($reason, $e->reason);
        }
    }

    // --- Fixture builders -------------------------------------------------------------------------

    private function flowWithAlice(
        ?UserVerificationRequirement $userVerification = null,
        bool $crossOriginAllowed = false,
    ): PasskeyFlow
    {
        $flow = $this->createFlow($userVerification, $crossOriginAllowed);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);
        $this->store->addCredential($this->record(self::ALICE_CREDENTIAL_ID, self::ALICE_HANDLE, $this->coseEntries));

        return $flow;
    }

    /**
     * With the passkey defaults, the concrete {@see PasskeyFlow} is used as-is; a policy override
     * exercises the intended customisation path — a subclass overriding the protected hook.
     */
    private function createFlow(
        ?UserVerificationRequirement $userVerification = null,
        bool $crossOriginAllowed = false,
    ): PasskeyFlow
    {
        if ($userVerification === null && !$crossOriginAllowed) {
            return new PasskeyFlow(self::RP_ID, 'Example RP', [self::ORIGIN], $this->store, $this->pending);
        }

        return new class (self::RP_ID, [self::ORIGIN], $this->store, $this->pending, $userVerification, $crossOriginAllowed) extends PasskeyFlow {

            /**
             * @param list<string> $origins
             */
            public function __construct(
                string $rpId,
                array $origins,
                PasskeyStore $store,
                PendingCeremonyStore $pendingStore,
                private readonly ?UserVerificationRequirement $userVerification,
                private readonly bool $crossOriginAllowed,
            )
            {
                parent::__construct($rpId, 'Example RP', $origins, $store, $pendingStore);
            }

            protected function getUserVerificationRequirement(): UserVerificationRequirement
            {
                return $this->userVerification ?? parent::getUserVerificationRequirement();
            }

            protected function isCrossOriginAllowed(): bool
            {
                return $this->crossOriginAllowed || parent::isCrossOriginAllowed();
            }

        };
    }

    /**
     * @param array<int, int|string> $coseEntries
     */
    private function record(
        string $credentialId,
        string $userHandle,
        array $coseEntries,
    ): CredentialRecord
    {
        return new CredentialRecord(
            credentialId: $credentialId,
            publicKey: CoseKey::fromCborMap(self::cborMap($coseEntries)),
            signCount: 0,
            userHandle: $userHandle,
            uvInitialized: true,
            backupEligible: false,
            backupState: false,
            transports: ['internal', 'hybrid'],
        );
    }

    private function aliceAssertion(
        string $challenge,
        int $signCount = 1,
        ?int $flags = null,
        bool $tamperSignature = false,
        ?bool $crossOrigin = null,
    ): string
    {
        return self::assertionBody(
            $this->privateKey,
            $challenge,
            self::ALICE_CREDENTIAL_ID,
            self::ALICE_HANDLE,
            signCount: $signCount,
            flags: $flags,
            tamperSignature: $tamperSignature,
            crossOrigin: $crossOrigin,
        );
    }

    /**
     * Builds the raw request body a browser would post after `navigator.credentials.create()`
     * with a `none`-format attestation object attesting the given COSE key.
     *
     * @param array<int, int|string>|null $coseEntries defaults to the ES256 fixture key
     */
    private function registrationBody(
        string $challenge,
        string $credentialId = self::NEW_CREDENTIAL_ID,
        ?array $coseEntries = null,
    ): string
    {
        $clientDataJson = json_encode([
            'type' => 'webauthn.create',
            'challenge' => Base64::urlEncode($challenge),
            'origin' => self::ORIGIN,
        ], JSON_THROW_ON_ERROR);

        $attestedCredentialData = self::AAGUID
            . pack('n', strlen($credentialId))
            . $credentialId
            . CborTestEncoder::intMap($coseEntries ?? $this->coseEntries);

        $authData = hash('sha256', self::RP_ID, binary: true)
            . chr(self::FLAGS_UP_UV | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA)
            . pack('N', 0)
            . $attestedCredentialData;

        $attestationObject = CborTestEncoder::map([
            [CborTestEncoder::textString('fmt'), CborTestEncoder::textString('none')],
            [CborTestEncoder::textString('attStmt'), CborTestEncoder::map([])],
            [CborTestEncoder::textString('authData'), CborTestEncoder::byteString($authData)],
        ]);

        return json_encode([
            'id' => Base64::urlEncode($credentialId),
            'rawId' => Base64::urlEncode($credentialId),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'attestationObject' => Base64::urlEncode($attestationObject),
                'transports' => ['internal'],
            ],
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Builds the raw request body a browser would post after `navigator.credentials.get()` —
     * the `PublicKeyCredential.toJSON()` output — signed live with the given key (ES256).
     */
    private static function assertionBody(
        OpenSSLAsymmetricKey $privateKey,
        string $challenge,
        string $credentialId,
        string $userHandle,
        int $signCount = 1,
        ?int $flags = null,
        bool $tamperSignature = false,
        ?bool $crossOrigin = null,
    ): string
    {
        $clientData = [
            'type' => 'webauthn.get',
            'challenge' => Base64::urlEncode($challenge),
            'origin' => self::ORIGIN,
        ];

        if ($crossOrigin !== null) {
            $clientData['crossOrigin'] = $crossOrigin;
        }

        $clientDataJson = json_encode($clientData, JSON_THROW_ON_ERROR);

        $authData = hash('sha256', self::RP_ID, binary: true)
            . chr($flags ?? self::FLAGS_UP_UV)
            . pack('N', $signCount);

        $signature = self::sign(
            $privateKey,
            $authData . hash('sha256', $clientDataJson, binary: true),
            CoseAlgorithmIdentifier::ES256,
        );

        if ($tamperSignature) {
            $signature[0] = chr(ord($signature[0]) ^ 0x01);
        }

        return json_encode([
            'id' => Base64::urlEncode($credentialId),
            'rawId' => Base64::urlEncode($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'authenticatorData' => Base64::urlEncode($authData),
                'signature' => Base64::urlEncode($signature),
                'userHandle' => Base64::urlEncode($userHandle),
            ],
        ], JSON_THROW_ON_ERROR);
    }

}
