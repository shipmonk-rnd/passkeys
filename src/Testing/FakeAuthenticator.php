<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Testing;

use LogicException;
use OpenSSLAsymmetricKey;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Base64\InvalidBase64Exception;
use ShipMonk\Passkeys\Cbor\CborEncoder;
use ShipMonk\Passkeys\Cose\CoseAlgorithmIdentifier;
use ShipMonk\Passkeys\Cose\CoseEc2Key;
use ShipMonk\Passkeys\Cose\CoseOkpKey;
use ShipMonk\Passkeys\Cose\CoseRsaKey;
use ShipMonk\Passkeys\Credential\AuthenticatorData;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use function array_map;
use function array_reverse;
use function chr;
use function hash;
use function in_array;
use function is_array;
use function is_int;
use function is_string;
use function json_encode;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_new;
use function openssl_sign;
use function pack;
use function parse_url;
use function random_bytes;
use function str_pad;
use function strlen;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_ED25519;
use const OPENSSL_KEYTYPE_ED448;
use const OPENSSL_KEYTYPE_RSA;
use const PHP_URL_HOST;
use const STR_PAD_LEFT;

/**
 * An in-memory software authenticator for integration-testing WebAuthn ceremonies end-to-end
 * without a browser: feed it the options JSON your endpoint produced and it returns the response
 * JSON a browser would post back — a `none`-format attestation for a fresh key pair on
 * {@see self::createPasskey()}, a real signature over `authenticatorData || SHA-256(clientDataJSON)`
 * on {@see self::authenticate()}.
 *
 * ```php
 * $authenticator = new FakeAuthenticator(origin: 'https://example.com');
 *
 * $optionsJson = $client->post('/register/options'); // your registration-options endpoint
 * $responseJson = $authenticator->createPasskey($optionsJson);
 * // post $responseJson to your registration-verify endpoint
 *
 * $optionsJson = $client->post('/login/options'); // your authentication-options endpoint
 * $responseJson = $authenticator->authenticate($optionsJson);
 * // post $responseJson to your authentication-verify endpoint
 * ```
 *
 * Like a real authenticator it keeps per-credential state ({@see FakePasskey}: key pair, user
 * handle, signature counter) across ceremonies, refuses creation when it already holds an
 * excluded credential, and honours `allowCredentials` when picking the passkey to assert with.
 * Behaviour that is a property of the authenticator/user rather than of one ceremony — user
 * presence/verification, backup state, the algorithm of generated keys — is configured once in
 * the constructor. Since none of this is an HTTP client, it composes with whatever drives your
 * endpoints (a framework test client, direct {@see \ShipMonk\Passkeys\Passkey\PasskeyFlow} calls, …).
 *
 * Malformed or unacceptable options throw a {@see LogicException} — in a test, both indicate a
 * bug, either in the relying party under test or in the test itself.
 *
 * @api
 */
final class FakeAuthenticator
{

    private const string AAGUID = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /**
     * @var list<FakePasskey>
     */
    private array $passkeys = [];

    /**
     * @param string                     $origin       the origin the fake "browser" is on, e.g. `https://example.com` — echoed into every `clientDataJSON`
     * @param CoseAlgorithmIdentifier::* $algorithm    the COSE algorithm of generated key pairs; creation fails when the options do not offer it
     * @param bool                       $userPresent  whether ceremonies set the User Present flag (a user gesture happened)
     * @param bool                       $userVerified whether ceremonies set the User Verified flag (PIN/biometric); disable to emulate e.g. a security key without a PIN
     * @param bool                       $backedUp     whether created passkeys report as backup-eligible and backed up (a synced passkey rather than a device-bound one)
     */
    public function __construct(
        private readonly string $origin,
        private readonly int $algorithm = CoseAlgorithmIdentifier::ES256,
        private readonly bool $userPresent = true,
        private readonly bool $userVerified = true,
        private readonly bool $backedUp = false,
    )
    {
    }

    /**
     * Emulates `navigator.credentials.create()`: parses the
     * {@see \ShipMonk\Passkeys\Options\PublicKeyCredentialCreationOptions} JSON, generates a fresh
     * key pair, remembers the new {@see FakePasskey}, and returns the registration response JSON
     * (`PublicKeyCredential.toJSON()` shape) to post to your verify endpoint.
     *
     * Mirroring a real client, it refuses (`InvalidStateError`) when `excludeCredentials` lists a
     * passkey it already holds for the RP, and (`NotSupportedError`) when `pubKeyCredParams` does
     * not offer the authenticator's algorithm.
     *
     * @param string $creationOptionsJson the JSON your registration-options endpoint returned
     */
    public function createPasskey(string $creationOptionsJson): string
    {
        try {
            $options = JsonObject::fromString($creationOptionsJson);
            $challenge = $options->getString('challenge');
            $rpId = $options->getObject('rp')->getOptionalString('id') ?? $this->originHost();
            $userHandle = $options->getObject('user')->getBytes('id');
            $offeredAlgorithms = array_map(
                static fn (JsonObject $parameters) => $parameters->getInt('alg'),
                $options->getObjectList('pubKeyCredParams'),
            );
            $excludedIds = array_map(
                static fn (JsonObject $descriptor) => $descriptor->getBytes('id'),
                $options->getOptionalObjectList('excludeCredentials') ?? [],
            );

        } catch (InvalidBase64Exception | JsonObjectException $e) {
            throw new LogicException('Malformed creation options: ' . $e->getMessage(), previous: $e);
        }

        if (!in_array($this->algorithm, $offeredAlgorithms, true)) {
            throw new LogicException(
                "The options do not offer the authenticator's algorithm {$this->algorithm} in pubKeyCredParams (NotSupportedError)",
            );
        }

        foreach ($this->passkeys as $passkey) {
            if ($passkey->rpId === $rpId && in_array($passkey->credentialId, $excludedIds, true)) {
                throw new LogicException(
                    'The authenticator already holds a credential listed in excludeCredentials (InvalidStateError)',
                );
            }
        }

        [$privateKey, $cosePublicKey] = $this->generateKeyPair();
        $credentialId = random_bytes(16);

        $attestedCredentialData = self::AAGUID
            . pack('n', strlen($credentialId))
            . $credentialId
            . $cosePublicKey;

        $authData = hash('sha256', $rpId, binary: true)
            . chr($this->flags() | AuthenticatorData::FLAG_ATTESTED_CREDENTIAL_DATA)
            . pack('N', 0)
            . $attestedCredentialData;

        $attestationObject = CborEncoder::encodeMap([
            [CborEncoder::encodeTextString('fmt'), CborEncoder::encodeTextString('none')],
            [CborEncoder::encodeTextString('attStmt'), CborEncoder::encodeMap([])],
            [CborEncoder::encodeTextString('authData'), CborEncoder::encodeByteString($authData)],
        ]);

        $this->passkeys[] = new FakePasskey($credentialId, $rpId, $userHandle, $this->algorithm, $privateKey);

        return self::encodeJson([
            'id' => Base64::urlEncode($credentialId),
            'rawId' => Base64::urlEncode($credentialId),
            'type' => 'public-key',
            'authenticatorAttachment' => 'platform',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($this->clientDataJson('webauthn.create', $challenge)),
                'attestationObject' => Base64::urlEncode($attestationObject),
                'transports' => ['internal'],
            ],
        ]);
    }

    /**
     * Emulates `navigator.credentials.get()`: parses the
     * {@see \ShipMonk\Passkeys\Options\PublicKeyCredentialRequestOptions} JSON, picks the passkey
     * to assert with — the most recently created one scoped to the RP ID and, when
     * `allowCredentials` is present, listed in it (like a real client, `NotAllowedError` when it
     * holds none) — increments its signature counter, signs, and returns the authentication
     * response JSON to post to your verify endpoint.
     *
     * @param string $requestOptionsJson the JSON your authentication-options endpoint returned
     */
    public function authenticate(string $requestOptionsJson): string
    {
        try {
            $options = JsonObject::fromString($requestOptionsJson);
            $challenge = $options->getString('challenge');
            $rpId = $options->getOptionalString('rpId') ?? $this->originHost();
            $allowList = $options->getOptionalObjectList('allowCredentials');
            $allowedIds = $allowList === null ? null : array_map(
                static fn (JsonObject $descriptor) => $descriptor->getBytes('id'),
                $allowList,
            );

        } catch (InvalidBase64Exception | JsonObjectException $e) {
            throw new LogicException('Malformed request options: ' . $e->getMessage(), previous: $e);
        }

        $passkey = $this->selectPasskey($rpId, $allowedIds);

        $authData = hash('sha256', $rpId, binary: true)
            . chr($this->flags())
            . pack('N', $passkey->nextSignCount());

        $clientDataJson = $this->clientDataJson('webauthn.get', $challenge);
        $signature = self::sign($passkey->privateKey, $authData . hash('sha256', $clientDataJson, binary: true), $passkey->algorithm);

        return self::encodeJson([
            'id' => Base64::urlEncode($passkey->credentialId),
            'rawId' => Base64::urlEncode($passkey->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64::urlEncode($clientDataJson),
                'authenticatorData' => Base64::urlEncode($authData),
                'signature' => Base64::urlEncode($signature),
                'userHandle' => Base64::urlEncode($passkey->userHandle),
            ],
        ]);
    }

    /**
     * The passkeys created so far, in creation order — e.g. to assert what got enrolled, or to
     * build a tampered response from {@see FakePasskey::$privateKey}.
     *
     * @return list<FakePasskey>
     */
    public function getPasskeys(): array
    {
        return $this->passkeys;
    }

    // --- Authenticator internals -----------------------------------------------------------------

    /**
     * @param list<string>|null $allowedIds
     */
    private function selectPasskey(
        string $rpId,
        ?array $allowedIds,
    ): FakePasskey
    {
        foreach (array_reverse($this->passkeys) as $passkey) {
            if ($passkey->rpId === $rpId && ($allowedIds === null || in_array($passkey->credentialId, $allowedIds, true))) {
                return $passkey;
            }
        }

        throw new LogicException("The authenticator holds no usable passkey for RP ID '{$rpId}' (NotAllowedError)");
    }

    private function flags(): int
    {
        return ($this->userPresent ? AuthenticatorData::FLAG_USER_PRESENT : 0)
            | ($this->userVerified ? AuthenticatorData::FLAG_USER_VERIFIED : 0)
            | ($this->backedUp ? AuthenticatorData::FLAG_BACKUP_ELIGIBILITY | AuthenticatorData::FLAG_BACKUP_STATE : 0);
    }

    private function clientDataJson(
        string $type,
        string $encodedChallenge,
    ): string
    {
        return self::encodeJson([
            'type' => $type,
            'challenge' => $encodedChallenge,
            'origin' => $this->origin,
            'crossOrigin' => false,
        ]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function encodeJson(array $data): string
    {
        return json_encode($data, JSON_THROW_ON_ERROR);
    }

    private function originHost(): string
    {
        $host = parse_url($this->origin, PHP_URL_HOST);

        if (!is_string($host)) {
            throw new LogicException("Cannot derive a default RP ID from origin '{$this->origin}'");
        }

        return $host;
    }

    // --- Crypto: key generation and signing --------------------------------------------------------

    /**
     * Generates a fresh key pair for the configured algorithm and returns the private key together
     * with the CBOR-encoded COSE public key, as an authenticator embeds it in attested credential data.
     *
     * @return array{OpenSSLAsymmetricKey, string}
     */
    private function generateKeyPair(): array
    {
        $algorithm = $this->algorithm;

        if ($algorithm === CoseAlgorithmIdentifier::RS256) {
            $key = self::newKey(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

            return [$key, self::coseMap([
                1 => CoseRsaKey::KTY,
                3 => $algorithm,
                -1 => self::keyDetail($key, 'rsa', 'n'),
                -2 => self::keyDetail($key, 'rsa', 'e'),
            ])];
        }

        if ($algorithm === CoseAlgorithmIdentifier::EdDSA
            || $algorithm === CoseAlgorithmIdentifier::Ed25519
            || $algorithm === CoseAlgorithmIdentifier::Ed448
        ) {
            [$keyType, $detailsGroup, $crv] = $algorithm === CoseAlgorithmIdentifier::Ed448
                ? [OPENSSL_KEYTYPE_ED448, 'ed448', CoseOkpKey::CRV_ED448]
                : [OPENSSL_KEYTYPE_ED25519, 'ed25519', CoseOkpKey::CRV_ED25519];
            $key = self::newKey(['private_key_type' => $keyType]);

            return [$key, self::coseMap([
                1 => CoseOkpKey::KTY,
                3 => $algorithm,
                -1 => $crv,
                -2 => self::keyDetail($key, $detailsGroup, 'pub_key'),
            ])];
        }

        [$curveName, $crv, $coordinateLength] = match ($algorithm) {
            CoseAlgorithmIdentifier::ES256 => ['prime256v1', CoseEc2Key::CRV_P256, 32],
            CoseAlgorithmIdentifier::ES384 => ['secp384r1', CoseEc2Key::CRV_P384, 48],
            CoseAlgorithmIdentifier::ES512 => ['secp521r1', CoseEc2Key::CRV_P521, 66],
        };
        $key = self::newKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);

        return [$key, self::coseMap([
            1 => CoseEc2Key::KTY,
            3 => $algorithm,
            -1 => $crv,
            -2 => str_pad(self::keyDetail($key, 'ec', 'x'), $coordinateLength, "\x00", STR_PAD_LEFT),
            -3 => str_pad(self::keyDetail($key, 'ec', 'y'), $coordinateLength, "\x00", STR_PAD_LEFT),
        ])];
    }

    /**
     * Signs a message with the digest the given COSE algorithm mandates, producing exactly the
     * signature encoding WebAuthn expects (ASN.1 DER for ECDSA, raw PKCS#1 for RSA, raw for EdDSA).
     *
     * @param CoseAlgorithmIdentifier::* $algorithm
     */
    private static function sign(
        OpenSSLAsymmetricKey $privateKey,
        string $message,
        int $algorithm,
    ): string
    {
        $digest = match ($algorithm) {
            CoseAlgorithmIdentifier::ES256, CoseAlgorithmIdentifier::RS256 => OPENSSL_ALGO_SHA256,
            CoseAlgorithmIdentifier::ES384 => OPENSSL_ALGO_SHA384,
            CoseAlgorithmIdentifier::ES512 => OPENSSL_ALGO_SHA512,
            // EdDSA is a pure signature scheme (no prehash)
            CoseAlgorithmIdentifier::EdDSA, CoseAlgorithmIdentifier::Ed25519, CoseAlgorithmIdentifier::Ed448 => 0,
        };

        if (!openssl_sign($message, $signature, $privateKey, $digest) || !is_string($signature)) {
            throw new LogicException('Failed to sign: ' . openssl_error_string());
        }

        return $signature;
    }

    /**
     * @param array<string, int|string> $config
     */
    private static function newKey(array $config): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new($config);

        if ($key === false) {
            throw new LogicException('Failed to generate a key pair: ' . openssl_error_string());
        }

        return $key;
    }

    private static function keyDetail(
        OpenSSLAsymmetricKey $key,
        string $group,
        string $field,
    ): string
    {
        $details = openssl_pkey_get_details($key);
        $value = is_array($details) && is_array($details[$group] ?? null) ? $details[$group][$field] ?? null : null;

        if (!is_string($value)) {
            throw new LogicException("Failed to read key detail {$group}.{$field}: " . openssl_error_string());
        }

        return $value;
    }

    /**
     * The COSE_Key CBOR map embedded in attested credential data: integer labels, with integer or
     * byte-string values.
     *
     * @param array<int, int|string> $entries
     */
    private static function coseMap(array $entries): string
    {
        $pairs = [];

        foreach ($entries as $label => $value) {
            $pairs[] = [
                CborEncoder::encodeInt($label),
                is_int($value) ? CborEncoder::encodeInt($value) : CborEncoder::encodeByteString($value),
            ];
        }

        return CborEncoder::encodeMap($pairs);
    }

}
