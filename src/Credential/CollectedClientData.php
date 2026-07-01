<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Base64\InvalidBase64Exception;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;
use WebAuthnX\Json\JsonObjectException;

/**
 * The client data collected by the browser, parsed from `clientDataJSON`.
 *
 * @see https://w3c.github.io/webauthn/#dictionary-client-data
 * @api
 */
readonly class CollectedClientData
{
	private function __construct(
		private string $type,
		private Bytes $challenge,
		private string $origin,
		private ?string $topOrigin,
		private ?bool $crossOrigin,
	) {
	}

	/**
	 * Parses and validates the raw `clientDataJSON` bytes, repacking any decode failure so the
	 * accessors below never throw.
	 *
	 * @throws MalformedDataException
	 */
	public static function fromBytes(Bytes $clientDataJSON): self
	{
		try {
			$object = JsonObject::fromBytes($clientDataJSON);

			return new self(
				$object->getString('type'),
				$object->getBytes('challenge'),
				$object->getString('origin'),
				$object->getOptionalString('topOrigin'),
				$object->getOptionalBoolean('crossOrigin'),
			);

		} catch (JsonObjectException | InvalidBase64Exception $e) {
			throw new MalformedDataException('Malformed client data', $e);
		}
	}

	public function getType(): string
	{
		return $this->type;
	}

	public function getChallenge(): Bytes
	{
		return $this->challenge;
	}

	public function getOrigin(): string
	{
		return $this->origin;
	}

	public function getTopOrigin(): ?string
	{
		return $this->topOrigin;
	}

	public function getCrossOrigin(): ?bool
	{
		return $this->crossOrigin;
	}
}
