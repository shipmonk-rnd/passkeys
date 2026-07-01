<?php declare(strict_types = 1);

namespace WebAuthnXTests;

use PHPUnit\Framework\TestCase;
use WebAuthnX\AttestationObject;
use WebAuthnX\Base64\Base64;
use WebAuthnX\Binary\Bytes;
use WebAuthnX\Binary\BytesReader;
use WebAuthnX\Cbor\CborMap;


class AuthenticatorDataTest extends TestCase
{
	public function testFromBytes(): void
	{
		$bytes = Bytes::fromBinaryString(Base64::urlDecode('o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFAAAAAAAAAAAAAAAAAAAAAAAAAAAAIPicKuaB2QMLvuZJAXn8nWNe4Y2iZKLDmWiYb0qo0l5fpQECAyYgASFYICAFU4dQcXT_GH1hZV2JoHHdVUCU_AkgGFd20UpKqAM0IlggJQzogT8UjnN7-tKvzIGk8e5OdWX1xurwC_sffQKh1a0'));
		BytesReader::read($bytes, function (BytesReader $reader) {
			$attObject = AttestationObject::fromCborMap(CborMap::fromBytesReader($reader));
			$authenticatorData = $attObject->parseAuthenticatorData();
		});
	}
}
