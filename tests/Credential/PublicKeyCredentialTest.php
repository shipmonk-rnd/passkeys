<?php declare(strict_types = 1);

namespace ShipMonk\PasskeysTests\Credential;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Credential\AuthenticatorAssertionResponse;
use ShipMonk\Passkeys\Credential\AuthenticatorAttestationResponse;
use ShipMonk\Passkeys\Credential\AuthenticatorResponse;
use ShipMonk\Passkeys\Credential\MalformedDataException;
use ShipMonk\Passkeys\Credential\PublicKeyCredential;
use ShipMonk\Passkeys\Enum\AuthenticatorAttachment;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialType;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use ShipMonk\PasskeysTests\PasskeysTestCase;
use function json_encode;
use const JSON_THROW_ON_ERROR;

#[CoversClass(PublicKeyCredential::class)]
#[CoversClass(AuthenticatorAttestationResponse::class)]
#[CoversClass(AuthenticatorAssertionResponse::class)]
#[CoversClass(AuthenticatorResponse::class)]
#[CoversClass(MalformedDataException::class)]
final class PublicKeyCredentialTest extends PasskeysTestCase
{

    private const string ATTESTATION_OBJECT = 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYql'
        . 'MGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPicKuaB2QMLvuZJAXn8nWNe4Y2iZKLDmWiYb0qo0l5fpQEC'
        . 'AyYgASFYICAFU4dQcXT_GH1hZV2JoHHdVUCU_AkgGFd20UpKqAM0IlggJQzogT8UjnN7-tKvzIGk8e5OdWX1xurwC_sffQKh1a0';

    /**
     * The parse boundary repacks the underlying decode failure into a single
     * {@see MalformedDataException}; the specific cause is preserved as its previous exception.
     *
     * @param callable(): mixed $cb
     *
     * @param-immediately-invoked-callable $cb
     */
    private static function assertMalformedData(
        string $previousMessage,
        callable $cb,
    ): void
    {
        try {
            $cb();
            self::fail('Expected a MalformedDataException');

        } catch (MalformedDataException $e) {
            $previous = $e->getPrevious();
            self::assertInstanceOf(JsonObjectException::class, $previous);
            self::assertStringMatchesFormat($previousMessage, $previous->getMessage());
        }
    }

    public function testFromRegistrationResponseJson(): void
    {
        $clientDataJson = '{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}';

        $credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'clientExtensionResults' => (object) [],
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'attestationObject' => self::ATTESTATION_OBJECT,
                'transports' => ['internal', 'hybrid'],
            ],
        ], JSON_THROW_ON_ERROR)));

        self::assertSame(PublicKeyCredentialType::PUBLIC_KEY, $credential->type);
        self::assertSame(Base64::urlEncode('credential-id'), $credential->id);
        self::assertSame('credential-id', $credential->rawId);
        self::assertSame(AuthenticatorAttachment::PLATFORM, $credential->authenticatorAttachment);
        self::assertNotNull($credential->clientExtensionResults);

        $response = $credential->response;
        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);
        self::assertSame(['internal', 'hybrid'], $response->transports);
        self::assertSame('none', $response->parseAttestationObject()->fmt);
        self::assertSame('webauthn.create', $response->parseClientData()->getType());
    }

    public function testRegistrationResponseWithoutTransports(): void
    {
        $credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.create"}'),
                'attestationObject' => self::ATTESTATION_OBJECT,
            ],
        ], JSON_THROW_ON_ERROR)));

        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);
        self::assertNull($credential->response->transports);
    }

    public function testParseAttestationObjectRejectsMalformedCbor(): void
    {
        $credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.create"}'),
                'attestationObject' => Base64::urlEncode('not-valid-cbor'),
            ],
        ], JSON_THROW_ON_ERROR)));

        $response = $credential->response;
        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        // The attestation object is stored raw and only parsed on demand, so the failure surfaces here.
        self::assertException(
            MalformedDataException::class,
            'Malformed attestation object',
            static fn () => $response->parseAttestationObject(),
        );
    }

    /**
     * The attestation object is one self-contained CBOR map, so undecodable CBOR and CBOR that
     * decodes to something other than a map must both be repacked into a MalformedDataException.
     */
    #[DataProvider('provideMalformedAttestationObject')]
    public function testParseAttestationObjectRejectsEveryDecodeFailure(string $attestationObject): void
    {
        $this->assertAttestationObjectRejected($attestationObject);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideMalformedAttestationObject(): iterable
    {
        yield 'undecodable CBOR' => ["\xff"];
        yield 'CBOR that is not a map' => ["\x01"];
    }

    /**
     * A complete attestation object is the *whole* of the member: a byte past its end must not be
     * silently ignored either.
     */
    public function testParseAttestationObjectRejectsTrailingBytes(): void
    {
        $this->assertAttestationObjectRejected(Base64::urlDecode(self::ATTESTATION_OBJECT) . "\x00");
    }

    private function assertAttestationObjectRejected(string $attestationObject): void
    {
        $credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.create"}'),
                'attestationObject' => Base64::urlEncode($attestationObject),
            ],
        ], JSON_THROW_ON_ERROR)));

        $response = $credential->response;
        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $response);

        self::assertException(
            MalformedDataException::class,
            'Malformed attestation object',
            static fn () => $response->parseAttestationObject(),
        );
    }

    /**
     * The base64url members are decoded while parsing the response, so invalid encoding fails the
     * same way a structurally wrong response does — never by letting InvalidBase64Exception out.
     */
    #[DataProvider('provideInvalidBase64Response')]
    public function testRejectsInvalidBase64UrlMembers(
        bool $registration,
        string $json,
    ): void
    {
        $jsonObject = JsonObject::fromString($json);

        self::assertException(
            MalformedDataException::class,
            $registration ? 'Malformed registration response' : 'Malformed authentication response',
            static fn () => $registration
                ? PublicKeyCredential::fromRegistrationResponseJson($jsonObject)
                : PublicKeyCredential::fromAuthenticationResponseJson($jsonObject),
        );
    }

    /**
     * @return iterable<string, array{bool, string}>
     */
    public static function provideInvalidBase64Response(): iterable
    {
        $registration = [
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.create"}'),
                'attestationObject' => self::ATTESTATION_OBJECT,
            ],
        ];

        $authentication = [
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.get"}'),
                'authenticatorData' => Base64::urlEncode('authenticator-data'),
                'signature' => Base64::urlEncode('signature'),
            ],
        ];

        $invalid = 'not base64url!';

        yield 'registration rawId' => [true, self::encodeWith($registration, ['rawId' => $invalid])];
        yield 'registration clientDataJSON' => [true, self::encodeWith($registration, ['response' => ['clientDataJSON' => $invalid] + $registration['response']])];
        yield 'authentication rawId' => [false, self::encodeWith($authentication, ['rawId' => $invalid])];
        yield 'authentication signature' => [false, self::encodeWith($authentication, ['response' => ['signature' => $invalid] + $authentication['response']])];
    }

    /**
     * @param array<string, mixed> $base
     * @param array<string, mixed> $overrides
     */
    private static function encodeWith(
        array $base,
        array $overrides,
    ): string
    {
        return json_encode($overrides + $base, JSON_THROW_ON_ERROR);
    }

    public function testFromAuthenticationResponseJson(): void
    {
        $clientDataJson = '{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com"}';

        $credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'authenticatorData' => Base64::urlEncode('authenticator-data'),
                'signature' => Base64::urlEncode('signature-bytes'),
                'userHandle' => Base64::urlEncode('user-handle'),
            ],
        ], JSON_THROW_ON_ERROR)));

        self::assertSame(PublicKeyCredentialType::PUBLIC_KEY, $credential->type);
        self::assertNull($credential->authenticatorAttachment);
        self::assertNull($credential->clientExtensionResults);

        $response = $credential->response;
        self::assertInstanceOf(AuthenticatorAssertionResponse::class, $response);
        self::assertSame('signature-bytes', $response->signature);
        self::assertSame('authenticator-data', $response->authenticatorData);
        self::assertNotNull($response->userHandle);
        self::assertSame('user-handle', $response->userHandle);
        self::assertSame('webauthn.get', $response->parseClientData()->getType());
    }

    public function testFromResponseJsonRejectsMissingResponse(): void
    {
        self::assertMalformedData(
            "Missing key 'response' in JSON object",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(self::jsonObject([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
            ])),
        );
    }

    public function testFromResponseJsonRejectsNonObjectResponse(): void
    {
        self::assertMalformedData(
            "Value of key 'response' is not an object",
            static fn () => PublicKeyCredential::fromAuthenticationResponseJson(self::jsonObject([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => 'not-an-object',
            ])),
        );
    }

    public function testFromAuthenticationResponseJsonWithoutUserHandle(): void
    {
        $credential = PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{"type":"webauthn.get"}'),
                'authenticatorData' => Base64::urlEncode('authenticator-data'),
                'signature' => Base64::urlEncode('signature-bytes'),
            ],
        ], JSON_THROW_ON_ERROR)));

        self::assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
        self::assertNull($credential->response->userHandle);
    }

    public function testRejectsUnexpectedType(): void
    {
        $this->expectException(MalformedDataException::class);
        $this->expectExceptionMessage("Unexpected credential type 'not-public-key'");

        PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'not-public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{}'),
                'attestationObject' => Base64::urlEncode('x'),
            ],
        ], JSON_THROW_ON_ERROR)));
    }

    public function testRejectsMissingTopLevelMember(): void
    {
        self::assertMalformedData(
            "Missing key 'id' in JSON object",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'attestationObject' => Base64::urlEncode('x'),
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    public function testRejectsMissingClientDataJsonInResponse(): void
    {
        self::assertMalformedData(
            "Missing key 'clientDataJSON' in JSON object",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => ['attestationObject' => Base64::urlEncode('x')],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    public function testRejectsMissingSignatureInResponse(): void
    {
        self::assertMalformedData(
            "Missing key 'signature' in JSON object",
            static fn () => PublicKeyCredential::fromAuthenticationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'authenticatorData' => Base64::urlEncode('authenticator-data'),
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    /**
     * An explicit JSON null for a required object member is reported as missing (getObject uses
     * isset semantics, for which JSON null is absent) — a null response is invalid either way.
     */
    public function testRejectsNullResponse(): void
    {
        self::assertMalformedData(
            "Missing key 'response' in JSON object",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => null,
            ], JSON_THROW_ON_ERROR))),
        );
    }

    /**
     * §5.1: relying parties SHOULD treat unknown `authenticatorAttachment` values as if the value
     * were null — a client reporting a future attachment modality must not break parsing.
     */
    public function testTreatsUnknownAuthenticatorAttachmentAsNull(): void
    {
        $credential = PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
            'id' => Base64::urlEncode('credential-id'),
            'rawId' => Base64::urlEncode('credential-id'),
            'type' => 'public-key',
            'authenticatorAttachment' => 'telepathy',
            'response' => [
                'clientDataJSON' => Base64::urlEncode('{}'),
                'attestationObject' => self::ATTESTATION_OBJECT,
            ],
        ], JSON_THROW_ON_ERROR)));

        self::assertNull($credential->authenticatorAttachment);
    }

    public function testRejectsNonStringAuthenticatorAttachment(): void
    {
        self::assertMalformedData(
            "Value of key 'authenticatorAttachment' is not a string",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'authenticatorAttachment' => 123,
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'attestationObject' => Base64::urlEncode('x'),
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    public function testRejectsNonStringType(): void
    {
        self::assertMalformedData(
            "Value of key 'type' is not a string",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 123,
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'attestationObject' => Base64::urlEncode('x'),
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    public function testRejectsNonArrayTransports(): void
    {
        self::assertMalformedData(
            "Value of key 'transports' is not an array",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'attestationObject' => Base64::urlEncode('x'),
                    'transports' => 'usb',
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

    public function testRejectsNonStringTransport(): void
    {
        self::assertMalformedData(
            "Value of key 'transports' is not an array of strings",
            static fn () => PublicKeyCredential::fromRegistrationResponseJson(JsonObject::fromString(json_encode([
                'id' => Base64::urlEncode('credential-id'),
                'rawId' => Base64::urlEncode('credential-id'),
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => Base64::urlEncode('{}'),
                    'attestationObject' => Base64::urlEncode('x'),
                    'transports' => [1, 2],
                ],
            ], JSON_THROW_ON_ERROR))),
        );
    }

}
