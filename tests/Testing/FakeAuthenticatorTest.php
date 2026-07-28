<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Testing;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Ceremony\VerificationException;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Enum\AuthenticatorAttachment;
use ShipMonk\Passkeys\PasskeyFlow;
use ShipMonk\Passkeys\PasskeyStore;
use ShipMonk\Passkeys\PendingCeremonyStore;
use ShipMonk\Passkeys\Testing\FakeAuthenticator;
use ShipMonk\Passkeys\Testing\FakePasskey;
use ShipMonk\PasskeysTests\InMemoryPasskeyStore;
use ShipMonk\PasskeysTests\InMemoryPendingCeremonyStore;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * Proves the {@see FakeAuthenticator} produces responses a real relying party accepts by driving
 * complete ceremonies through {@see PasskeyFlow} — exactly how a consumer's integration test
 * would use it — plus the authenticator-side behaviours (credential selection, refusals,
 * UP/UV/backup flags) a browser would exhibit.
 */
#[CoversClass(FakeAuthenticator::class)]
#[CoversClass(FakePasskey::class)]
final class FakeAuthenticatorTest extends PasskeysTestCase
{

    private const string RP_ID = 'example.com';
    private const string ORIGIN = 'https://example.com';

    private const string ALICE = 'alice@example.com';
    private const string ALICE_HANDLE = 'alice-handle-0001';
    private const string BOB = 'bob@example.com';
    private const string BOB_HANDLE = 'bob-handle-000002';

    private InMemoryPasskeyStore $store;

    private InMemoryPendingCeremonyStore $pending;

    protected function setUp(): void
    {
        $this->store = new InMemoryPasskeyStore();
        $this->pending = new InMemoryPendingCeremonyStore();
    }

    /**
     * @param CoseAlgorithmIdentifier::* $algorithm
     */
    #[DataProvider('provideAlgorithms')]
    public function testRegistrationThenAuthenticationRoundTrip(int $algorithm): void
    {
        $flow = $this->createFlow($algorithm);
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, algorithm: $algorithm);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        $registered = $flow->register(
            $authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()),
        );

        self::assertSame(self::ALICE_HANDLE, $registered->userHandle);
        self::assertSame(AuthenticatorAttachment::PLATFORM, $registered->authenticatorAttachment);
        self::assertTrue($registered->result->userVerified);
        self::assertSame(['internal'], $registered->toCredentialRecord()->transports);

        // A default authenticator is a single-device one: not backup eligible, so never backed up.
        self::assertFalse($registered->result->backupEligible);
        self::assertFalse($registered->result->backupState);

        $passkey = $authenticator->getPasskeys()[0] ?? null;
        self::assertNotNull($passkey);
        self::assertSame($registered->result->credentialId, $passkey->credentialId);
        self::assertSame(self::RP_ID, $passkey->rpId);
        self::assertSame(self::ALICE_HANDLE, $passkey->userHandle);

        // The passkey works for a usernameless login, then for a pinned two-step login,
        // with the signature counter increasing like a real authenticator's.
        $first = $flow->authenticate($authenticator->authenticate($flow->authenticationOptions()->toJson()));
        self::assertSame(self::ALICE_HANDLE, $first->userHandle);
        self::assertSame(1, $first->newSignCount);
        self::assertFalse($first->possibleClone);

        $second = $flow->authenticate($authenticator->authenticate($flow->authenticationOptions(self::ALICE)->toJson()));
        self::assertSame(2, $second->newSignCount);
        self::assertSame(2, $passkey->signCount);
    }

    /**
     * @return iterable<string, array{CoseAlgorithmIdentifier::*}>
     */
    public static function provideAlgorithms(): iterable
    {
        yield 'ES256' => [CoseAlgorithmIdentifier::ES256];
        yield 'ES384' => [CoseAlgorithmIdentifier::ES384];
        yield 'ES512' => [CoseAlgorithmIdentifier::ES512];
        yield 'RS256' => [CoseAlgorithmIdentifier::RS256];
        yield 'EdDSA' => [CoseAlgorithmIdentifier::EdDSA];
        yield 'Ed448' => [CoseAlgorithmIdentifier::Ed448];
    }

    public function testAllowCredentialsPinsThePasskeyChoice(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);
        $this->store->addUser(self::BOB, self::BOB_HANDLE);

        $flow->register($authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()));
        $flow->register($authenticator->createPasskey($flow->registrationOptions(self::BOB_HANDLE, self::BOB)->toJson()));

        // Without an allow-list the most recently created passkey (bob's) is used…
        $usernameless = $flow->authenticate($authenticator->authenticate($flow->authenticationOptions()->toJson()));
        self::assertSame(self::BOB_HANDLE, $usernameless->userHandle);

        // …while alice's pinned two-step options make the authenticator pick her passkey.
        $pinned = $flow->authenticate($authenticator->authenticate($flow->authenticationOptions(self::ALICE)->toJson()));
        self::assertSame(self::ALICE_HANDLE, $pinned->userHandle);
    }

    public function testRefusesCreationForExcludedCredential(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        $flow->register($authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()));

        // The account's second registration excludes its existing credential, so the same
        // authenticator must refuse to enrol again — as a real client does (InvalidStateError).
        self::assertException(
            LogicException::class,
            '%aInvalidStateError%a',
            static fn () => $authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()),
        );
        self::assertCount(1, $authenticator->getPasskeys());
    }

    public function testRefusesCreationWhenAlgorithmIsNotOffered(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, algorithm: CoseAlgorithmIdentifier::ES384);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        // The flow's default algorithms (ES256/RS256/EdDSA) do not include ES384.
        self::assertException(
            LogicException::class,
            '%aNotSupportedError%a',
            static fn () => $authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()),
        );
    }

    public function testRefusesAssertionWithoutUsablePasskey(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN);

        self::assertException(
            LogicException::class,
            '%aNotAllowedError%a',
            static fn () => $authenticator->authenticate($flow->authenticationOptions()->toJson()),
        );
    }

    public function testUnverifiedUserIsRejectedByDefaultFlowPolicy(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, userVerified: false);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        // A consumer can integration-test its negative paths the same way: the fake emulates a
        // PIN-less security key, the flow's default policy demands user verification.
        self::assertException(
            VerificationException::class,
            'User Verified flag is not set',
            static fn () => $flow->register($authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson())),
        );
    }

    public function testAbsentUserIsRejected(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, userPresent: false);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        self::assertException(
            VerificationException::class,
            'User Present flag is not set',
            static fn () => $flow->register($authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson())),
        );
    }

    /**
     * The silent passkey upgrade: a conditional-mediation creation happens without any user
     * interaction, so the fake emulates it with neither flag set — and the flow, which relaxes both
     * checks for that ceremony, accepts it.
     */
    public function testSilentCreationSetsNeitherUserFlag(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, userPresent: false, userVerified: false);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        $registered = $flow->register($authenticator->createPasskey(
            $flow->registrationOptions(self::ALICE_HANDLE, self::ALICE, conditionalMediation: true)->toJson(),
        ));

        self::assertTrue($registered->conditionalMediation);
        self::assertFalse($registered->result->userVerified);
        self::assertFalse($registered->toCredentialRecord()->uvInitialized);
    }

    public function testBackedUpPasskeyReportsBackupFlags(): void
    {
        $flow = $this->createFlow();
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN, backedUp: true);
        $this->store->addUser(self::ALICE, self::ALICE_HANDLE);

        $registered = $flow->register(
            $authenticator->createPasskey($flow->registrationOptions(self::ALICE_HANDLE, self::ALICE)->toJson()),
        );

        self::assertTrue($registered->result->backupEligible);
        self::assertTrue($registered->result->backupState);
    }

    public function testRpIdDefaultsToOriginHost(): void
    {
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN);

        // Hand-built minimal options exercise the spec-optional members: no rp.id, no rpId.
        $authenticator->createPasskey(json_encode([
            'challenge' => Base64::urlEncode('a-challenge-of-32-bytes-length!!'),
            'rp' => ['name' => 'Example RP'],
            'user' => [
                'id' => Base64::urlEncode(self::ALICE_HANDLE),
                'name' => self::ALICE,
                'displayName' => self::ALICE,
            ],
            'pubKeyCredParams' => [['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::ES256]],
        ], JSON_THROW_ON_ERROR));

        $passkey = $authenticator->getPasskeys()[0] ?? null;
        self::assertNotNull($passkey);
        self::assertSame(self::RP_ID, $passkey->rpId);

        $responseJson = $authenticator->authenticate(json_encode([
            'challenge' => Base64::urlEncode('another-challenge-32-bytes-long!'),
        ], JSON_THROW_ON_ERROR));

        self::assertStringContainsString(Base64::urlEncode($passkey->credentialId), $responseJson);
        self::assertSame(1, $passkey->signCount);
    }

    /**
     * A relying party may scope its credentials to a registrable suffix of the origin, so an
     * explicit `rp.id` / `rpId` has to be honoured as given — the origin host is only the fallback
     * for when the options omit it.
     */
    public function testExplicitRpIdIsUsedInsteadOfTheOriginHost(): void
    {
        $authenticator = new FakeAuthenticator(origin: 'https://login.example.com');

        $authenticator->createPasskey(json_encode([
            'challenge' => Base64::urlEncode('a-challenge-of-32-bytes-length!!'),
            'rp' => ['name' => 'Example RP', 'id' => self::RP_ID],
            'user' => [
                'id' => Base64::urlEncode(self::ALICE_HANDLE),
                'name' => self::ALICE,
                'displayName' => self::ALICE,
            ],
            'pubKeyCredParams' => [['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::ES256]],
        ], JSON_THROW_ON_ERROR));

        $passkey = $authenticator->getPasskeys()[0] ?? null;
        self::assertNotNull($passkey);
        self::assertSame(self::RP_ID, $passkey->rpId);

        // The assertion side resolves the RP ID the same way, so it finds that very passkey.
        $authenticator->authenticate(json_encode([
            'challenge' => Base64::urlEncode('another-challenge-32-bytes-long!'),
            'rpId' => self::RP_ID,
        ], JSON_THROW_ON_ERROR));

        self::assertSame(1, $passkey->signCount);
    }

    #[DataProvider('provideMalformedOptions')]
    public function testMalformedOptionsAreRejected(
        bool $creation,
        string $optionsJson,
        string $message,
    ): void
    {
        $authenticator = new FakeAuthenticator(origin: self::ORIGIN);

        self::assertException(
            LogicException::class,
            $message,
            static fn () => $creation
                ? $authenticator->createPasskey($optionsJson)
                : $authenticator->authenticate($optionsJson),
        );
    }

    /**
     * @return iterable<string, array{bool, string, string}>
     */
    public static function provideMalformedOptions(): iterable
    {
        yield 'creation options that are not JSON' => [true, 'not json', 'Malformed creation options: %a'];
        yield 'request options with a non-string challenge' => [false, '{"challenge": 42}', 'Malformed request options: %a'];

        // Members the options carry base64url-encoded fail the same way a structural problem does.
        yield 'creation options with an invalid base64url user id' => [
            true,
            json_encode([
                'challenge' => Base64::urlEncode('a-challenge-of-32-bytes-length!!'),
                'rp' => ['name' => 'Example RP', 'id' => self::RP_ID],
                'user' => ['id' => 'not base64url!', 'name' => self::ALICE, 'displayName' => self::ALICE],
                'pubKeyCredParams' => [['type' => 'public-key', 'alg' => CoseAlgorithmIdentifier::ES256]],
            ], JSON_THROW_ON_ERROR),
            'Malformed creation options: %a',
        ];

        yield 'request options with an invalid base64url credential id' => [
            false,
            json_encode([
                'challenge' => Base64::urlEncode('another-challenge-32-bytes-long!'),
                'rpId' => self::RP_ID,
                'allowCredentials' => [['type' => 'public-key', 'id' => 'not base64url!']],
            ], JSON_THROW_ON_ERROR),
            'Malformed request options: %a',
        ];
    }

    /**
     * A flow whose policy accepts the given algorithm — the subclass mirrors how a consumer with
     * a non-default algorithm policy would set it up.
     *
     * @param CoseAlgorithmIdentifier::* $algorithm
     */
    private function createFlow(int $algorithm = CoseAlgorithmIdentifier::ES256): PasskeyFlow
    {
        if ($algorithm === CoseAlgorithmIdentifier::ES256) {
            return new PasskeyFlow(self::RP_ID, 'Example RP', [self::ORIGIN], $this->store, $this->pending);
        }

        return new class (self::RP_ID, [self::ORIGIN], $this->store, $this->pending, $algorithm) extends PasskeyFlow {

            /**
             * @param list<string>               $origins
             * @param CoseAlgorithmIdentifier::* $algorithm
             */
            public function __construct(
                string $rpId,
                array $origins,
                PasskeyStore $store,
                PendingCeremonyStore $pendingStore,
                private readonly int $algorithm,
            )
            {
                parent::__construct($rpId, 'Example RP', $origins, $store, $pendingStore);
            }

            protected function getAllowedAlgorithms(): array
            {
                return [$this->algorithm];
            }

        };
    }

}
