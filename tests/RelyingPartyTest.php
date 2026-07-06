<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\CredentialRecord;
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Ceremony\RegistrationResult;
use WebAuthnX\Cose\CoseAlgorithmIdentifier;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Credential\AuthenticatorAssertionResponse;
use WebAuthnX\Credential\AuthenticatorAttestationResponse;
use WebAuthnX\Credential\AuthenticatorData;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\RelyingParty;
use WebAuthnXTests\Cbor\CborTestEncoder;
use WebAuthnXTests\Ceremony\InMemoryCredentialStore;

use function chr;
use function hash;
use function json_encode;
use function ord;
use function pack;
use function str_repeat;
use function strlen;

use const JSON_THROW_ON_ERROR;

/**
 * Exercises the {@see RelyingParty} façade end-to-end: a full registration → authentication
 * round trip with real crypto for every supported algorithm, then one negative per WebAuthn
 * §7.1 / §7.2 check, asserting the exact {@see VerificationException} reason each raises.
 *
 * Fixtures are assembled the way an authenticator/browser would emit them (see the builders at
 * the bottom); signatures are produced live because ECDSA output is non-deterministic.
 */
class RelyingPartyTest extends CryptoTestCase
{
    private const string RP_ID = 'example.com';
    private const string ORIGIN = 'https://example.com';
    private const string CHALLENGE = 'a-fixed-32-byte-challenge-value!';
    private const string USER_HANDLE = 'user-handle-0001';
    private const string CREDENTIAL_ID = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a";
    private const string AAGUID = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

    private const int FLAGS_UP_UV = AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_USER_VERIFIED;

    /** @var array<int, int|string> */
    private array $coseEntries;

    private OpenSSLAsymmetricKey $privateKey;

    protected function setUp(): void
    {
        // A single ES256 key pair backs the (non-algorithm-specific) negative cases.
        [$this->privateKey, $this->coseEntries] = self::generateKeyAndCoseEntries(CoseAlgorithmIdentifier::ES256);
    }

    // --- Happy path: full round trip for every supported algorithm ------------------------------

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRegistrationThenAuthenticationRoundTrip(int $alg): void
    {
        [$privateKey, $coseEntries] = self::generateKeyAndCoseEntries($alg);
        $relyingParty = new RelyingParty();
        $store = new InMemoryCredentialStore();

        $registration = $relyingParty->verifyRegistration(
            self::registrationCredential($coseEntries),
            self::registrationExpectations(allowedAlgorithms: [$alg]),
            $store,
        );

        self::assertSame(self::CREDENTIAL_ID, $registration->credentialId);
        self::assertSame($alg, $registration->publicKey->alg);
        self::assertSame(0, $registration->signCount);
        self::assertTrue($registration->userVerified);
        self::assertSame(self::AAGUID, $registration->aaguid);
        self::assertSame(['internal'], $registration->transports);
        self::assertSame(RegistrationResult::ATTESTATION_NONE, $registration->attestationType);

        $store->add($registration->toCredentialRecord(self::USER_HANDLE));

        $authentication = $relyingParty->verifyAuthentication(
            self::authenticationCredential($privateKey, $alg, signCount: 5),
            self::authenticationExpectations(),
            $store,
        );

        self::assertSame(self::CREDENTIAL_ID, $authentication->credentialId);
        self::assertSame(self::USER_HANDLE, $authentication->userHandle);
        self::assertSame(5, $authentication->newSignCount);
        self::assertTrue($authentication->userVerified);
        self::assertFalse($authentication->possibleClone);
    }

    /**
     * @param CoseAlgorithmIdentifier::* $alg
     */
    #[DataProvider('provideAlgorithms')]
    public function testRegistrationVerifiesPackedSelfAttestation(int $alg): void
    {
        [$privateKey, $coseEntries] = self::generateKeyAndCoseEntries($alg);

        $result = (new RelyingParty())->verifyRegistration(
            self::registrationCredential($coseEntries, fmt: 'packed', attestationKey: $privateKey, attestationAlg: $alg),
            self::registrationExpectations(allowedAlgorithms: [$alg]),
            new InMemoryCredentialStore(),
        );

        self::assertSame(RegistrationResult::ATTESTATION_SELF, $result->attestationType);
        self::assertSame($alg, $result->publicKey->alg);
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
    }

    // --- Registration: policy toggles & the pre-identified authentication branch ----------------

    public function testRegistrationHonoursConditionalMediationAndCrossOrigin(): void
    {
        // No User Present bit, but conditional mediation relaxes the requirement; cross-origin allowed.
        $credential = self::registrationCredential(
            $this->coseEntries,
            crossOrigin: true,
            flags: AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA,
        );

        $result = (new RelyingParty())->verifyRegistration(
            $credential,
            self::registrationExpectations(conditionalMediation: true, allowCrossOrigin: true),
            new InMemoryCredentialStore(),
        );

        self::assertFalse($result->userVerified);
    }

    public function testAuthenticationAcceptsPreIdentifiedUser(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, userHandle: null),
            self::authenticationExpectations(
                allowedCredentialIds: [self::CREDENTIAL_ID],
                expectedUserHandle: self::USER_HANDLE,
            ),
            $store,
        );

        self::assertSame(self::USER_HANDLE, $result->userHandle);
    }

    public function testAuthenticationFlagsPossibleCloneOnCounterRegression(): void
    {
        $store = self::storeWith($this->registeredRecord(signCount: 10));

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, signCount: 4),
            self::authenticationExpectations(),
            $store,
        );

        self::assertTrue($result->possibleClone);
        self::assertSame(4, $result->newSignCount);
    }

    public function testAuthenticationDoesNotFlagCloneWhenBothCountersZero(): void
    {
        $store = self::storeWith($this->registeredRecord(signCount: 0));

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, signCount: 0),
            self::authenticationExpectations(),
            $store,
        );

        self::assertFalse($result->possibleClone);
    }

    // --- Registration negatives -----------------------------------------------------------------

    public function testRegistrationRejectsWrongClientDataType(): void
    {
        $this->assertRegistrationFails(
            VerificationException::INVALID_CLIENT_DATA_TYPE,
            self::registrationCredential($this->coseEntries, type: 'webauthn.get'),
        );
    }

    public function testRegistrationRejectsChallengeMismatch(): void
    {
        $this->assertRegistrationFails(
            VerificationException::CHALLENGE_MISMATCH,
            self::registrationCredential($this->coseEntries, challenge: 'a-completely-different-challenge!'),
        );
    }

    public function testRegistrationRejectsUntrustedOrigin(): void
    {
        $this->assertRegistrationFails(
            VerificationException::UNTRUSTED_ORIGIN,
            self::registrationCredential($this->coseEntries, origin: 'https://evil.example'),
        );
    }

    public function testRegistrationRejectsDisallowedCrossOrigin(): void
    {
        $this->assertRegistrationFails(
            VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
            self::registrationCredential($this->coseEntries, crossOrigin: true),
        );
    }

    public function testRegistrationRejectsRpIdHashMismatch(): void
    {
        $this->assertRegistrationFails(
            VerificationException::RP_ID_MISMATCH,
            self::registrationCredential($this->coseEntries, rpId: 'evil.example'),
        );
    }

    public function testRegistrationRejectsMissingUserPresent(): void
    {
        $this->assertRegistrationFails(
            VerificationException::USER_NOT_PRESENT,
            self::registrationCredential($this->coseEntries, flags: AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA),
        );
    }

    public function testRegistrationRejectsMissingUserVerifiedWhenRequired(): void
    {
        $credential = self::registrationCredential(
            $this->coseEntries,
            flags: AuthenticatorData::FLAG_USER_PRESENT | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA,
        );

        $this->assertVerificationFailure(VerificationException::USER_NOT_VERIFIED, static fn () =>
            (new RelyingParty())->verifyRegistration(
                $credential,
                self::registrationExpectations(requireUserVerification: true),
                new InMemoryCredentialStore(),
            ));
    }

    public function testRegistrationRejectsBackupStateWithoutEligibility(): void
    {
        $this->assertRegistrationFails(
            VerificationException::INVALID_BACKUP_STATE,
            self::registrationCredential($this->coseEntries, flags: self::FLAGS_UP_UV
                | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA
                | AuthenticatorData::FLAG_BACKUP_STATE),
        );
    }

    public function testRegistrationRejectsMissingAttestedCredentialData(): void
    {
        $this->assertRegistrationFails(
            VerificationException::MISSING_ATTESTED_CREDENTIAL_DATA,
            self::registrationCredential($this->coseEntries, flags: self::FLAGS_UP_UV, includeAttestedCredentialData: false),
        );
    }

    public function testRegistrationRejectsUnsupportedAlgorithm(): void
    {
        $credential = self::registrationCredential($this->coseEntries);

        $this->assertVerificationFailure(VerificationException::UNSUPPORTED_ALGORITHM, static fn () =>
            (new RelyingParty())->verifyRegistration(
                $credential,
                self::registrationExpectations(allowedAlgorithms: [CoseAlgorithmIdentifier::RS256]),
                new InMemoryCredentialStore(),
            ));
    }

    public function testRegistrationRejectsUnsupportedAttestationFormat(): void
    {
        $this->assertRegistrationFails(
            VerificationException::UNSUPPORTED_ATTESTATION_FORMAT,
            self::registrationCredential($this->coseEntries, fmt: 'fido-u2f'),
        );
    }

    public function testRegistrationRejectsPackedAttestationWithCertificateChain(): void
    {
        // x5c present means Basic/AttCA attestation (§8.2), which needs the deferred X.509 layer.
        $attStmt = CborTestEncoder::map([
            [CborTestEncoder::textString('alg'), CborTestEncoder::int(CoseAlgorithmIdentifier::ES256)],
            [CborTestEncoder::textString('sig'), CborTestEncoder::byteString('irrelevant')],
            [CborTestEncoder::textString('x5c'), CborTestEncoder::byteString('certificate-chain-placeholder')],
        ]);

        $this->assertRegistrationFails(
            VerificationException::UNSUPPORTED_ATTESTATION_FORMAT,
            self::registrationCredential($this->coseEntries, fmt: 'packed', attStmtOverride: $attStmt),
        );
    }

    public function testRegistrationRejectsPackedSelfAttestationWithMissingFields(): void
    {
        // fmt `packed` with an empty attStmt: no x5c makes it self attestation, but alg/sig are missing.
        $this->assertRegistrationFails(
            VerificationException::INVALID_ATTESTATION_STATEMENT,
            self::registrationCredential($this->coseEntries, fmt: 'packed'),
        );
    }

    public function testRegistrationRejectsPackedSelfAttestationAlgorithmMismatch(): void
    {
        $this->assertRegistrationFails(
            VerificationException::INVALID_ATTESTATION_STATEMENT,
            self::registrationCredential(
                $this->coseEntries,
                fmt: 'packed',
                attestationKey: $this->privateKey,
                attestationAlg: CoseAlgorithmIdentifier::ES256,
                attStmtAlgOverride: CoseAlgorithmIdentifier::RS256,
            ),
        );
    }

    public function testRegistrationRejectsUnusableAttestedKey(): void
    {
        // Same off-curve key trick as {@see testAuthenticationRejectsUnusableStoredKey}: the all-zero
        // P-256 point parses as COSE and passes the algorithm allow-list, but OpenSSL refuses to load
        // it when the self-attestation signature is checked.
        $coseEntries = [
            1 => 2,
            3 => CoseAlgorithmIdentifier::ES256,
            -1 => 1,
            -2 => str_repeat("\x00", 32),
            -3 => str_repeat("\x00", 32),
        ];

        $attStmt = CborTestEncoder::map([
            [CborTestEncoder::textString('alg'), CborTestEncoder::int(CoseAlgorithmIdentifier::ES256)],
            [CborTestEncoder::textString('sig'), CborTestEncoder::byteString('irrelevant')],
        ]);

        $this->assertRegistrationFails(
            VerificationException::UNUSABLE_CREDENTIAL_KEY,
            self::registrationCredential($coseEntries, fmt: 'packed', attStmtOverride: $attStmt),
        );
    }

    public function testRegistrationRejectsPackedSelfAttestationWithBadSignature(): void
    {
        $this->assertRegistrationFails(
            VerificationException::INVALID_ATTESTATION_STATEMENT,
            self::registrationCredential(
                $this->coseEntries,
                fmt: 'packed',
                attestationKey: $this->privateKey,
                attestationAlg: CoseAlgorithmIdentifier::ES256,
                tamperAttestationSignature: true,
            ),
        );
    }

    public function testRegistrationRejectsOversizedCredentialId(): void
    {
        $this->assertRegistrationFails(
            VerificationException::CREDENTIAL_ID_TOO_LONG,
            self::registrationCredential($this->coseEntries, credentialId: str_repeat("\x2a", 1024)),
        );
    }

    public function testRegistrationRejectsAlreadyRegisteredCredential(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertVerificationFailure(VerificationException::CREDENTIAL_ALREADY_REGISTERED, fn () =>
            (new RelyingParty())->verifyRegistration(
                self::registrationCredential($this->coseEntries),
                self::registrationExpectations(),
                $store,
            ));
    }

    // --- Authentication negatives ---------------------------------------------------------------

    public function testAuthenticationRejectsCredentialOutsideAllowList(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertVerificationFailure(VerificationException::CREDENTIAL_NOT_ALLOWED, fn () =>
            (new RelyingParty())->verifyAuthentication(
                self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256),
                self::authenticationExpectations(allowedCredentialIds: ["\x00\x01\x02"]),
                $store,
            ));
    }

    public function testAuthenticationRejectsUnknownCredential(): void
    {
        $this->assertAuthenticationFails(
            VerificationException::UNKNOWN_CREDENTIAL,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256),
            new InMemoryCredentialStore(),
        );
    }

    public function testAuthenticationRejectsMissingUserHandleWhenUsernameless(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::MISSING_USER_HANDLE,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, userHandle: null),
            $store,
        );
    }

    public function testAuthenticationRejectsUserHandleMismatchWhenUsernameless(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::USER_HANDLE_MISMATCH,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, userHandle: 'someone-else'),
            $store,
        );
    }

    public function testAuthenticationRejectsRecordNotBelongingToIdentifiedUser(): void
    {
        $store = self::storeWith($this->registeredRecord(userHandle: 'a-different-user'));

        $this->assertVerificationFailure(VerificationException::USER_HANDLE_MISMATCH, fn () =>
            (new RelyingParty())->verifyAuthentication(
                self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, userHandle: null),
                self::authenticationExpectations(expectedUserHandle: self::USER_HANDLE),
                $store,
            ));
    }

    public function testAuthenticationRejectsReturnedUserHandleMismatchingIdentifiedUser(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertVerificationFailure(VerificationException::USER_HANDLE_MISMATCH, fn () =>
            (new RelyingParty())->verifyAuthentication(
                self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, userHandle: 'someone-else'),
                self::authenticationExpectations(expectedUserHandle: self::USER_HANDLE),
                $store,
            ));
    }

    public function testAuthenticationRejectsWrongClientDataType(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::INVALID_CLIENT_DATA_TYPE,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, type: 'webauthn.create'),
            $store,
        );
    }

    public function testAuthenticationRejectsChallengeMismatch(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::CHALLENGE_MISMATCH,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, challenge: 'a-completely-different-challenge!'),
            $store,
        );
    }

    public function testAuthenticationRejectsUntrustedOrigin(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::UNTRUSTED_ORIGIN,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, origin: 'https://evil.example'),
            $store,
        );
    }

    public function testAuthenticationRejectsDisallowedCrossOrigin(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, crossOrigin: true),
            $store,
        );
    }

    public function testAuthenticationRejectsRpIdHashMismatch(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::RP_ID_MISMATCH,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, rpId: 'evil.example'),
            $store,
        );
    }

    public function testAuthenticationRejectsMissingUserPresent(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::USER_NOT_PRESENT,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, flags: AuthenticatorData::FLAG_USER_VERIFIED),
            $store,
        );
    }

    public function testAuthenticationRejectsMissingUserVerifiedWhenRequired(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertVerificationFailure(VerificationException::USER_NOT_VERIFIED, fn () =>
            (new RelyingParty())->verifyAuthentication(
                self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, flags: AuthenticatorData::FLAG_USER_PRESENT),
                self::authenticationExpectations(requireUserVerification: true),
                $store,
            ));
    }

    public function testAuthenticationRejectsBackupStateWithoutEligibility(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::INVALID_BACKUP_STATE,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, flags: self::FLAGS_UP_UV | AuthenticatorData::FLAG_BACKUP_STATE),
            $store,
        );
    }

    public function testAuthenticationRejectsChangedBackupEligibility(): void
    {
        // The stored record was not backup eligible; the assertion now claims it is.
        $store = self::storeWith($this->registeredRecord(backupEligible: false));

        $this->assertAuthenticationFails(
            VerificationException::BACKUP_ELIGIBILITY_CHANGED,
            self::authenticationCredential(
                $this->privateKey,
                CoseAlgorithmIdentifier::ES256,
                flags: self::FLAGS_UP_UV | AuthenticatorData::FLAG_BACKUP_ELIGIBILITY,
            ),
            $store,
        );
    }

    public function testAuthenticationRejectsTamperedSignature(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::INVALID_SIGNATURE,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, tamperSignature: true),
            $store,
        );
    }

    public function testAuthenticationRejectsUnusableStoredKey(): void
    {
        // An EC2 P-256 key (kty 2, crv 1) with an off-curve, all-zero point parses but cannot be
        // loaded by OpenSSL, so verification raises a SignatureVerificationException that the façade
        // repacks into a VerificationException.
        $record = new CredentialRecord(
            credentialId: self::CREDENTIAL_ID,
            publicKey: CoseKey::fromCborMap(self::cborMap([
                1 => 2,
                3 => CoseAlgorithmIdentifier::ES256,
                -1 => 1,
                -2 => str_repeat("\x00", 32),
                -3 => str_repeat("\x00", 32),
            ])),
            signCount: 0,
            userHandle: self::USER_HANDLE,
            uvInitialized: true,
            backupEligible: false,
            backupState: false,
        );

        $this->assertAuthenticationFails(
            VerificationException::UNUSABLE_CREDENTIAL_KEY,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256),
            self::storeWith($record),
        );
    }

    public function testAuthenticationFlagsPossibleCloneOnEqualNonZeroCounter(): void
    {
        $store = self::storeWith($this->registeredRecord(signCount: 7));

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, signCount: 7),
            self::authenticationExpectations(),
            $store,
        );

        self::assertTrue($result->possibleClone);
    }

    public function testAuthenticationTreatsEmptyAllowListAsUsernameless(): void
    {
        // An empty allowCredentials list applies no membership check, exactly like a null list.
        $store = self::storeWith($this->registeredRecord());

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256),
            self::authenticationExpectations(allowedCredentialIds: []),
            $store,
        );

        self::assertSame(self::USER_HANDLE, $result->userHandle);
    }

    // --- topOrigin (§7.1 step 11 / §7.2 step 14) ------------------------------------------------

    public function testRegistrationRejectsTopOriginWhenCrossOriginDisallowed(): void
    {
        $this->assertRegistrationFails(
            VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
            self::registrationCredential($this->coseEntries, topOrigin: 'https://embedder.example'),
        );
    }

    public function testRegistrationRejectsUntrustedTopOrigin(): void
    {
        $credential = self::registrationCredential($this->coseEntries, crossOrigin: true, topOrigin: 'https://embedder.example');

        $this->assertVerificationFailure(VerificationException::UNTRUSTED_TOP_ORIGIN, static fn () =>
            (new RelyingParty())->verifyRegistration(
                $credential,
                self::registrationExpectations(allowCrossOrigin: true, allowedTopOrigins: ['https://trusted.example']),
                new InMemoryCredentialStore(),
            ));
    }

    public function testAuthenticationAcceptsAllowedTopOrigin(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $result = (new RelyingParty())->verifyAuthentication(
            self::authenticationCredential(
                $this->privateKey,
                CoseAlgorithmIdentifier::ES256,
                crossOrigin: true,
                topOrigin: 'https://embedder.example',
            ),
            self::authenticationExpectations(allowCrossOrigin: true, allowedTopOrigins: ['https://embedder.example']),
            $store,
        );

        self::assertSame(self::USER_HANDLE, $result->userHandle);
    }

    // --- Malformed responses fail closed as VerificationException -------------------------------

    public function testRegistrationRejectsMalformedAttestationObject(): void
    {
        $this->assertRegistrationFails(
            VerificationException::MALFORMED_RESPONSE,
            self::registrationCredential($this->coseEntries, attestationObjectOverride: 'not-valid-cbor-at-all'),
        );
    }

    public function testAuthenticationRejectsMalformedAuthenticatorData(): void
    {
        $store = self::storeWith($this->registeredRecord());

        $this->assertAuthenticationFails(
            VerificationException::MALFORMED_RESPONSE,
            self::authenticationCredential($this->privateKey, CoseAlgorithmIdentifier::ES256, authDataOverride: "\x00\x01\x02"),
            $store,
        );
    }

    // --- Expectations reject a weak challenge ---------------------------------------------------

    public function testRegistrationExpectationsRejectShortChallenge(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RegistrationExpectations(
            challenge: 'too-short',
            rpId: self::RP_ID,
            origins: [self::ORIGIN],
            allowedAlgorithms: [CoseAlgorithmIdentifier::ES256],
        );
    }

    public function testAuthenticationExpectationsRejectShortChallenge(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AuthenticationExpectations(
            challenge: 'too-short',
            rpId: self::RP_ID,
            origins: [self::ORIGIN],
        );
    }

    // --- Assertion helpers ----------------------------------------------------------------------

    /**
     * @param  VerificationException::*                              $reason
     * @param  PublicKeyCredential<AuthenticatorAttestationResponse> $credential
     */
    private function assertRegistrationFails(string $reason, PublicKeyCredential $credential): void
    {
        $this->assertVerificationFailure($reason, static fn () =>
            (new RelyingParty())->verifyRegistration($credential, self::registrationExpectations(), new InMemoryCredentialStore()));
    }

    /**
     * @param  VerificationException::*                           $reason
     * @param  PublicKeyCredential<AuthenticatorAssertionResponse> $credential
     */
    private function assertAuthenticationFails(string $reason, PublicKeyCredential $credential, InMemoryCredentialStore $store): void
    {
        $this->assertVerificationFailure($reason, static fn () =>
            (new RelyingParty())->verifyAuthentication($credential, self::authenticationExpectations(), $store));
    }

    /**
     * @param  VerificationException::* $expectedReason
     * @param  callable(): mixed        $cb
     * @param-immediately-invoked-callable $cb
     */
    private function assertVerificationFailure(string $expectedReason, callable $cb): void
    {
        try {
            $cb();
            self::fail("Expected a VerificationException with reason '{$expectedReason}'");

        } catch (VerificationException $e) {
            self::assertSame($expectedReason, $e->reason);
        }
    }

    // --- Fixture builders -----------------------------------------------------------------------

    /**
     * @param  list<CoseAlgorithmIdentifier::*> $allowedAlgorithms
     * @param  list<string> $allowedTopOrigins
     */
    private static function registrationExpectations(
        array $allowedAlgorithms = [CoseAlgorithmIdentifier::ES256],
        bool $requireUserVerification = false,
        bool $allowCrossOrigin = false,
        array $allowedTopOrigins = [],
        bool $conditionalMediation = false,
    ): RegistrationExpectations {
        return new RegistrationExpectations(
            challenge: self::CHALLENGE,
            rpId: self::RP_ID,
            origins: [self::ORIGIN],
            allowedAlgorithms: $allowedAlgorithms,
            requireUserVerification: $requireUserVerification,
            allowCrossOrigin: $allowCrossOrigin,
            allowedTopOrigins: $allowedTopOrigins,
            conditionalMediation: $conditionalMediation,
        );
    }

    /**
     * @param  list<string>|null $allowedCredentialIds
     * @param  list<string>     $allowedTopOrigins
     */
    private static function authenticationExpectations(
        ?array $allowedCredentialIds = null,
        bool $requireUserVerification = false,
        bool $allowCrossOrigin = false,
        array $allowedTopOrigins = [],
        ?string $expectedUserHandle = null,
    ): AuthenticationExpectations {
        return new AuthenticationExpectations(
            challenge: self::CHALLENGE,
            rpId: self::RP_ID,
            origins: [self::ORIGIN],
            allowedCredentialIds: $allowedCredentialIds,
            requireUserVerification: $requireUserVerification,
            allowCrossOrigin: $allowCrossOrigin,
            allowedTopOrigins: $allowedTopOrigins,
            expectedUserHandle: $expectedUserHandle,
        );
    }

    private function registeredRecord(
        int $signCount = 0,
        string $userHandle = self::USER_HANDLE,
        bool $backupEligible = false,
    ): CredentialRecord {
        return new CredentialRecord(
            credentialId: self::CREDENTIAL_ID,
            publicKey: CoseKey::fromCborMap(self::cborMap($this->coseEntries)),
            signCount: $signCount,
            userHandle: $userHandle,
            uvInitialized: true,
            backupEligible: $backupEligible,
            backupState: false,
        );
    }

    private static function storeWith(CredentialRecord $record): InMemoryCredentialStore
    {
        $store = new InMemoryCredentialStore();
        $store->add($record);

        return $store;
    }

    /**
     * `$attestationKey`/`$attestationAlg` build a `packed` self-attestation statement signed live
     * over `authData ‖ SHA-256(clientDataJSON)`; `$attStmtAlgOverride` declares a different `alg`
     * in the statement than was used to sign, and `$attStmtOverride` replaces the statement CBOR
     * wholesale (for the x5c / missing-field negatives).
     *
     * @param  array<int, int|string> $coseEntries
     * @param  CoseAlgorithmIdentifier::*|null $attestationAlg
     * @return PublicKeyCredential<AuthenticatorAttestationResponse>
     */
    private static function registrationCredential(
        array $coseEntries,
        string $type = 'webauthn.create',
        string $challenge = self::CHALLENGE,
        string $origin = self::ORIGIN,
        ?bool $crossOrigin = null,
        string $rpId = self::RP_ID,
        ?int $flags = null,
        int $signCount = 0,
        string $fmt = 'none',
        string $credentialId = self::CREDENTIAL_ID,
        bool $includeAttestedCredentialData = true,
        ?string $topOrigin = null,
        ?string $attestationObjectOverride = null,
        ?OpenSSLAsymmetricKey $attestationKey = null,
        ?int $attestationAlg = null,
        ?int $attStmtAlgOverride = null,
        bool $tamperAttestationSignature = false,
        ?string $attStmtOverride = null,
    ): PublicKeyCredential {
        $flags ??= self::FLAGS_UP_UV | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA;

        $attestedCredentialData = $includeAttestedCredentialData
            ? self::AAGUID . pack('n', strlen($credentialId)) . $credentialId . CborTestEncoder::intMap($coseEntries)
            : null;

        $authData = self::authenticatorData($rpId, $flags, $signCount, $attestedCredentialData);
        $clientDataJson = self::clientDataJson($type, $challenge, $origin, $crossOrigin, $topOrigin);

        $attStmt = $attStmtOverride ?? CborTestEncoder::map([]);

        if ($attestationKey !== null && $attestationAlg !== null) {
            $signature = self::sign(
                $attestationKey,
                $authData . hash('sha256', $clientDataJson, binary: true),
                $attestationAlg,
            );

            if ($tamperAttestationSignature) {
                $signature[0] = chr(ord($signature[0]) ^ 0x01);
            }

            $attStmt = CborTestEncoder::map([
                [CborTestEncoder::textString('alg'), CborTestEncoder::int($attStmtAlgOverride ?? $attestationAlg)],
                [CborTestEncoder::textString('sig'), CborTestEncoder::byteString($signature)],
            ]);
        }

        $attestationObject = $attestationObjectOverride ?? CborTestEncoder::map([
            [CborTestEncoder::textString('fmt'), CborTestEncoder::textString($fmt)],
            [CborTestEncoder::textString('attStmt'), $attStmt],
            [CborTestEncoder::textString('authData'), CborTestEncoder::byteString($authData)],
        ]);

        return PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode($credentialId),
            'rawId' => Base64::urlEncode($credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'attestationObject' => Base64::urlEncode($attestationObject),
                'transports' => ['internal'],
            ],
        ], JSON_THROW_ON_ERROR)));
    }

    /**
     * @param  CoseAlgorithmIdentifier::* $alg
     * @return PublicKeyCredential<AuthenticatorAssertionResponse>
     */
    private static function authenticationCredential(
        OpenSSLAsymmetricKey $privateKey,
        int $alg,
        string $type = 'webauthn.get',
        string $challenge = self::CHALLENGE,
        string $origin = self::ORIGIN,
        ?bool $crossOrigin = null,
        string $rpId = self::RP_ID,
        ?int $flags = null,
        int $signCount = 1,
        string $credentialId = self::CREDENTIAL_ID,
        ?string $userHandle = self::USER_HANDLE,
        bool $tamperSignature = false,
        ?string $topOrigin = null,
        ?string $authDataOverride = null,
    ): PublicKeyCredential {
        $flags ??= self::FLAGS_UP_UV;
        $authData = $authDataOverride ?? self::authenticatorData($rpId, $flags, $signCount, null);
        $clientDataJson = self::clientDataJson($type, $challenge, $origin, $crossOrigin, $topOrigin);

        $signature = self::sign($privateKey, $authData . hash('sha256', $clientDataJson, binary: true), $alg);

        if ($tamperSignature) {
            $signature[0] = chr(ord($signature[0]) ^ 0x01);
        }

        $response = [
            'clientDataJSON' => Base64::urlEncode($clientDataJson),
            'authenticatorData' => Base64::urlEncode($authData),
            'signature' => Base64::urlEncode($signature),
        ];

        if ($userHandle !== null) {
            $response['userHandle'] = Base64::urlEncode($userHandle);
        }

        return PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode($credentialId),
            'rawId' => Base64::urlEncode($credentialId),
            'type' => 'public-key',
            'response' => $response,
        ], JSON_THROW_ON_ERROR)));
    }

    private static function authenticatorData(string $rpId, int $flags, int $signCount, ?string $attestedCredentialData): string
    {
        return hash('sha256', $rpId, binary: true)
            . chr($flags)
            . pack('N', $signCount)
            . ($attestedCredentialData ?? '');
    }

    private static function clientDataJson(string $type, string $challenge, string $origin, ?bool $crossOrigin, ?string $topOrigin): string
    {
        $data = [
            'type' => $type,
            'challenge' => Base64::urlEncode($challenge),
            'origin' => $origin,
        ];

        if ($crossOrigin !== null) {
            $data['crossOrigin'] = $crossOrigin;
        }

        if ($topOrigin !== null) {
            $data['topOrigin'] = $topOrigin;
        }

        return json_encode($data, JSON_THROW_ON_ERROR);
    }
}
