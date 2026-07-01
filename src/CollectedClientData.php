<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Binary\Bytes;
use WebAuthnX\Json\JsonObject;


readonly class CollectedClientData
{
	public function __construct(
		private JsonObject $object,
	) {
	}


	public function getType(): string
	{
		return $this->object->getString('type');
	}


	public function getChallenge(): Bytes
	{
		return $this->object->getBytes('challenge');
	}


	public function getOrigin(): string
	{
		return $this->object->getString('origin');
	}


	public function getTopOrigin(): ?string
	{
		return $this->object->getOptionalString('topOrigin');
	}


	public function getCrossOrigin(): ?bool
	{
		return $this->object->getOptionalBoolean('crossOrigin');
	}
}
