<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use WebAuthnX\Base64\InvalidBase64Exception;
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
    /**
     * @param string $challenge raw challenge bytes (base64url-decoded from the JSON member)
     */
    private function __construct(
        private string $type,
        private string $challenge,
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
    public static function fromBytes(string $clientDataJSON): self
    {
        try {
            $object = JsonObject::fromString($clientDataJSON);

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

    /**
     * @return string raw challenge bytes (not base64url-encoded)
     */
    public function getChallenge(): string
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
