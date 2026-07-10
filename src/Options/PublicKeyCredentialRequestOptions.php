<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialHint;
use ShipMonk\Passkeys\Enum\UserVerificationRequirement;
use stdClass;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * Options for an authentication ceremony, serializable to the
 * {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptionsjson PublicKeyCredentialRequestOptionsJSON}
 * form consumed by the browser.
 *
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions
 * @api
 */
readonly class PublicKeyCredentialRequestOptions implements JsonSerializable
{

    /**
     * The recommended default ceremony timeout (§15.1: recommended range 300 000–600 000 ms).
     *
     * @see https://w3c.github.io/webauthn/#sctn-timeout-recommended-range
     */
    public const int RECOMMENDED_TIMEOUT = 300_000;

    /**
     * @param string                                   $challenge        raw challenge bytes (e.g. from {@see \random_bytes()}); base64url encoding happens on serialization
     * @param list<PublicKeyCredentialDescriptor>|null $allowCredentials
     * @param list<PublicKeyCredentialHint>|null       $hints
     * @param array<string, mixed>|null                $extensions       client extension inputs in their JSON form ({@link https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputsjson AuthenticationExtensionsClientInputsJSON})
     */
    public function __construct(
        public string $challenge,
        public ?int $timeout = self::RECOMMENDED_TIMEOUT,
        public ?string $rpId = null,
        public ?array $allowCredentials = null,
        public ?UserVerificationRequirement $userVerification = null,
        public ?array $hints = null,
        public ?array $extensions = null,
    )
    {
    }

    /**
     * @return array{
     *     challenge: string,
     *     timeout?: int,
     *     rpId?: string,
     *     allowCredentials?: list<PublicKeyCredentialDescriptor>,
     *     userVerification?: UserVerificationRequirement,
     *     hints?: list<PublicKeyCredentialHint>,
     *     extensions?: stdClass,
     * }
     */
    public function jsonSerialize(): array
    {
        $data = [
            'challenge' => Base64::urlEncode($this->challenge),
        ];

        if ($this->timeout !== null) {
            $data['timeout'] = $this->timeout;
        }

        if ($this->rpId !== null) {
            $data['rpId'] = $this->rpId;
        }

        if ($this->allowCredentials !== null) {
            $data['allowCredentials'] = $this->allowCredentials;
        }

        if ($this->userVerification !== null) {
            $data['userVerification'] = $this->userVerification;
        }

        if ($this->hints !== null) {
            $data['hints'] = $this->hints;
        }

        if ($this->extensions !== null) {
            $data['extensions'] = (object) $this->extensions; // cast so an empty map serializes as {} (a JSON object), never []
        }

        return $data;
    }

    public function toJson(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR);
    }

}
