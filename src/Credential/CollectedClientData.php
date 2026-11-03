<?php declare(strict_types = 1);

namespace ShipMonk\Passkeys\Credential;

use ShipMonk\Passkeys\Base64\InvalidBase64Exception;
use ShipMonk\Passkeys\Json\JsonObject;
use ShipMonk\Passkeys\Json\JsonObjectException;
use function str_starts_with;
use function substr;

/**
 * The client data collected by the browser, parsed from `clientDataJSON`.
 *
 * @see https://www.w3.org/TR/webauthn-3/#dictionary-client-data
 * @api
 */
final readonly class CollectedClientData
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
    )
    {
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
            // WebAuthn §7.1 / §7.2 UTF-8 decoding consumes one leading BOM for parsing only.
            // The response retains the original bytes, including the BOM, for signature hashing.
            $json = str_starts_with($clientDataJSON, "\xEF\xBB\xBF") ? substr($clientDataJSON, 3) : $clientDataJSON;
            $object = JsonObject::fromString($json);

            return new self(
                $object->getString('type'),
                $object->getBytes('challenge'),
                $object->getString('origin'),
                $object->getOptionalString('topOrigin'),
                $object->getOptionalBoolean('crossOrigin'),
            );

        } catch (InvalidBase64Exception | JsonObjectException $e) {
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
