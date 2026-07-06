<?php declare(strict_types = 1);

namespace WebAuthnX\Options;

use JsonSerializable;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Enum\PublicKeyCredentialHints;

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
readonly class PublicKeyCredentialCreationOptions implements JsonSerializable
{
	/**
	 * The recommended default ceremony timeout (§15.1: recommended range 300 000–600 000 ms).
	 *
	 * @see https://w3c.github.io/webauthn/#sctn-timeout-recommended-range
	 */
	public const RECOMMENDED_TIMEOUT = 300_000;

	/**
	 * `$timeout` defaults to {@see self::RECOMMENDED_TIMEOUT}; pass null to omit it and let the
	 * client apply its own default. `$extensions` are the client extension inputs in their JSON
	 * form ({@link https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputsjson
	 * AuthenticationExtensionsClientInputsJSON}), passed through verbatim — binary values must
	 * already be base64url-encoded strings, e.g. `['credProps' => true]`.
	 *
	 * @param  list<PublicKeyCredentialParameters>      $pubKeyCredParams
	 * @param  list<PublicKeyCredentialDescriptor>|null $excludeCredentials
	 * @param  list<PublicKeyCredentialHints::*>|null   $hints
	 * @param  array<string, mixed>|null                $extensions
	 */
	public function __construct(
		public PublicKeyCredentialRpEntity $rp,
		public PublicKeyCredentialUserEntity $user,
		public Bytes $challenge,
		public array $pubKeyCredParams,
		public ?int $timeout = self::RECOMMENDED_TIMEOUT,
		public ?array $excludeCredentials = null,
		public ?AuthenticatorSelectionCriteria $authenticatorSelection = null,
		public ?array $hints = null,
		public ?array $extensions = null,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function jsonSerialize(): array
	{
		$data = [
			'rp' => $this->rp,
			'user' => $this->user,
			'challenge' => Base64::urlEncode($this->challenge->toBinaryString()),
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
			// Cast so an empty map serializes as {} (a JSON object), never [].
			$data['extensions'] = (object) $this->extensions;
		}

		return $data;
	}

	public function toJson(): string
	{
		// Default escaping (slashes escaped to "<\/…") is kept deliberately: it neutralises a
		// "</script>" breakout if a relying party inlines this JSON into an HTML <script> block.
		return json_encode($this, JSON_THROW_ON_ERROR);
	}
}
