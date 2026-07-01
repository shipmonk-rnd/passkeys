<?php declare(strict_types = 1);

namespace WebAuthnX\Credential;

use RuntimeException;
use Throwable;

/**
 * Thrown when a credential response cannot be decoded into its typed form — malformed JSON,
 * base64url, CBOR, authenticator-data bytes, or an unusable COSE key.
 *
 * This is the single "the input is malformed" type the credential-parsing boundary presents,
 * repacking the specific low-level decode exceptions (which stay internal to the primitive
 * `Base64` / `Binary` / `Cbor` / `Cose` / `Json` layers) so callers of the parse methods have
 * one exception to handle rather than six. The original cause is retained as {@see getPrevious()}.
 */
final class MalformedDataException extends RuntimeException
{
	public function __construct(string $message, ?Throwable $previous = null)
	{
		parent::__construct($message, previous: $previous);
	}
}
