<?php declare(strict_types = 1);

namespace WebAuthnX\Base64;

/**
 * @see https://www.rfc-editor.org/rfc/rfc4648.html#section-5
 */
class Base64
{
	public static function urlEncode(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}


	/**
	 * @throws InvalidBase64Exception
	 */
	public static function urlDecode(string $data): string
	{
		if ($data !== '' && preg_match('~^[A-Za-z0-9_-]+$~', $data) !== 1) {
			throw new InvalidBase64Exception('Invalid base64url data');
		}

		$base64 = strtr($data, '-_', '+/');
		$base64 .= str_repeat('=', (4 - strlen($base64) % 4) % 4);

		$decoded = base64_decode($base64, strict: true);

		if ($decoded === false) {
			throw new InvalidBase64Exception('Invalid base64url data');
		}

		return $decoded;
	}
}
