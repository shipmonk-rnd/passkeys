<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Options;

use JsonSerializable;
use ShipMonk\Passkeys\Base64\Base64;
use ShipMonk\Passkeys\Enum\PublicKeyCredentialHint;
use stdClass;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * Options for a registration ceremony, serializable to the
 * {@link https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson PublicKeyCredentialCreationOptionsJSON}
 * form consumed by the browser.
 *
 * @see https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
 * @api
 */
final readonly class PublicKeyCredentialCreationOptions implements JsonSerializable
{

    /**
     * The recommended default ceremony timeout (§15.1: recommended range 300 000–600 000 ms).
     *
     * @see https://w3c.github.io/webauthn/#sctn-timeout-recommended-range
     */
    public const int RECOMMENDED_TIMEOUT = 300_000;

    /**
     * @param string                                   $challenge          raw challenge bytes (e.g. from {@see \random_bytes()})
     * @param list<PublicKeyCredentialParameters>      $pubKeyCredParams
     * @param list<PublicKeyCredentialDescriptor>|null $excludeCredentials
     * @param list<PublicKeyCredentialHint>|null       $hints
     * @param array<string, mixed>|null                $extensions         client extension inputs in their JSON form ({@link https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputsjson AuthenticationExtensionsClientInputsJSON})
     */
    public function __construct(
        public PublicKeyCredentialRpEntity $rp,
        public PublicKeyCredentialUserEntity $user,
        public string $challenge,
        public array $pubKeyCredParams,
        public ?int $timeout = self::RECOMMENDED_TIMEOUT,
        public ?array $excludeCredentials = null,
        public ?AuthenticatorSelectionCriteria $authenticatorSelection = null,
        public ?array $hints = null,
        public ?array $extensions = null,
    )
    {
    }

    /**
     * @return array{
     *     rp: PublicKeyCredentialRpEntity,
     *     user: PublicKeyCredentialUserEntity,
     *     challenge: string,
     *     pubKeyCredParams: list<PublicKeyCredentialParameters>,
     *     timeout?: int,
     *     excludeCredentials?: list<PublicKeyCredentialDescriptor>,
     *     authenticatorSelection?: AuthenticatorSelectionCriteria,
     *     hints?: list<PublicKeyCredentialHint>,
     *     extensions?: stdClass,
     *  }
     */
    public function jsonSerialize(): array
    {
        $data = [
            'rp' => $this->rp,
            'user' => $this->user,
            'challenge' => Base64::urlEncode($this->challenge),
            'pubKeyCredParams' => $this->pubKeyCredParams,
        ];

        if ($this->timeout !== null) {
            $data['timeout'] = $this->timeout;
        }

        if ($this->excludeCredentials !== null) {
            $data['excludeCredentials'] = $this->excludeCredentials;
        }

        if ($this->authenticatorSelection !== null) {
            $data['authenticatorSelection'] = $this->authenticatorSelection;
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
