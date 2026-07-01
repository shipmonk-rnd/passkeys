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
		$decoded = base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '='));

		if ($decoded === false) {
			throw new InvalidBase64Exception('Invalid base64url data');
		}

		return $decoded;
	}
}
