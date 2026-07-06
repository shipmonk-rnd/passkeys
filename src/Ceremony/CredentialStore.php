<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

/**
 * The relying party's read access to its stored credentials, keyed by credential id.
 *
 * The library owns no persistence: it calls {@see self::findCredentialByCredentialId()} to enforce the
 * "not already registered" check of WebAuthn §7.1 step 26 and to locate the credential record
 * for an assertion (§7.2 step 6). Because credential ids are globally unique, a single lookup
 * by id serves both the pre-identified and the discoverable (usernameless) authentication flows.
 * Persisting new records and updating the sign counter after a successful ceremony is the
 * caller's responsibility, driven by the returned result objects.
 *
 * @api
 */
interface CredentialStore
{
	/**
	 * @param string $credentialId raw credential id bytes (not base64url-encoded)
	 */
	public function findCredentialByCredentialId(string $credentialId): ?CredentialRecord;
}
