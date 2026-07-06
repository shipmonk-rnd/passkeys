<?php declare(strict_types = 1);

namespace WebAuthnX;

use WebAuthnX\Ceremony\AuthenticationExpectations;
use WebAuthnX\Ceremony\AuthenticationResult;
use WebAuthnX\Ceremony\CredentialStore;
use WebAuthnX\Ceremony\RegistrationExpectations;
use WebAuthnX\Ceremony\RegistrationResult;
use WebAuthnX\Ceremony\VerificationException;
use WebAuthnX\Cbor\CborMapException;
use WebAuthnX\Cose\CoseKey;
use WebAuthnX\Credential\AttestationObject;
use WebAuthnX\Credential\AuthenticatorAssertionResponse;
use WebAuthnX\Credential\AuthenticatorAttestationResponse;
use WebAuthnX\Credential\AuthenticatorData;
use WebAuthnX\Credential\CollectedClientData;
use WebAuthnX\Credential\MalformedDataException;
use WebAuthnX\Credential\PublicKeyCredential;
use WebAuthnX\Cose\SignatureVerificationException;

use function hash;
use function hash_equals;
use function in_array;
use function strlen;

/**
 * The relying-party façade: it runs the full WebAuthn §7.1 (registration) and §7.2
 * (authentication) verification procedures over an already-parsed {@see PublicKeyCredential},
 * turning it into a trustworthy {@see RegistrationResult} / {@see AuthenticationResult} or, on
 * any failed check, a {@see VerificationException}.
 *
 * This implementation covers the common `attestation: "none"` deployment: it accepts the `none`
 * attestation format without evaluating a trust path (§7.1 steps 22–24 collapse to the "None
 * attestation acceptable" case), and verifies `packed` **self** attestation (§8.2 without `x5c`)
 * against the credential public key — which clients pass through unmodified even when the relying
 * party asked for `attestation: "none"` (§5.1.3). Every other format, including `packed` with an
 * `x5c` certificate chain, is rejected as unsupported; that trust-path evaluation is a planned
 * later layer.
 *
 * The library holds no state: expectations are passed in per ceremony and credential records are
 * read through a caller-supplied {@see CredentialStore}. Persisting new records and the updated
 * sign counter is the caller's job, driven by the returned result objects. It likewise does not
 * track challenge single-use — the caller must invalidate a challenge after one ceremony, which
 * is the actual anti-replay control (ECDSA low-S is not enforced, so assertion signature bytes
 * must not be used for replay de-duplication).
 *
 * @see https://w3c.github.io/webauthn/#sctn-registering-a-new-credential §7.1
 * @see https://w3c.github.io/webauthn/#sctn-verifying-assertion §7.2
 * @api
 */
final class RelyingParty
{
	private const string TYPE_CREATE = 'webauthn.create';
	private const string TYPE_GET = 'webauthn.get';

	/** {@link https://w3c.github.io/webauthn/#credential-id Credential IDs} are at most 1023 bytes (§7.1 step 25). */
	private const int MAX_CREDENTIAL_ID_LENGTH = 1023;

	private const string FMT_NONE = 'none';
	private const string FMT_PACKED = 'packed';

	/**
	 * Verifies a registration ceremony response (`navigator.credentials.create()`) per WebAuthn §7.1.
	 *
	 * @param  PublicKeyCredential<AuthenticatorAttestationResponse> $credential
	 * @throws VerificationException on any failed §7.1 check, if the response is malformed, or if
	 *     the attested credential key is unusable (unsupported algorithm / cannot be loaded)
	 */
	public function verifyRegistration(
		PublicKeyCredential $credential,
		RegistrationExpectations $expectations,
		CredentialStore $store,
	): RegistrationResult {
		try {
			return $this->doVerifyRegistration($credential, $expectations, $store);

		} catch (MalformedDataException $e) {
			throw new VerificationException(
				VerificationException::MALFORMED_RESPONSE,
				'Malformed registration response: ' . $e->getMessage(),
				$e,
			);

		} catch (SignatureVerificationException $e) {
			// The attested key already passed COSE parsing and the algorithm allow-list, so
			// if OpenSSL still cannot load it, the key material itself is at fault.
			throw new VerificationException(
				VerificationException::UNUSABLE_CREDENTIAL_KEY,
				'Attested credential key is unusable: ' . $e->getMessage(),
				$e,
			);
		}
	}

	/**
	 * @param  PublicKeyCredential<AuthenticatorAttestationResponse> $credential
	 * @throws VerificationException
	 * @throws MalformedDataException
	 * @throws SignatureVerificationException
	 */
	private function doVerifyRegistration(
		PublicKeyCredential $credential,
		RegistrationExpectations $expectations,
		CredentialStore $store,
	): RegistrationResult {
		$response = $credential->response;
		$clientData = $response->parseClientData();

		// §7.1 step 7: the client asserts this data was collected for a creation ceremony.
		if ($clientData->getType() !== self::TYPE_CREATE) {
			throw new VerificationException(
				VerificationException::INVALID_CLIENT_DATA_TYPE,
				"Expected client data type '" . self::TYPE_CREATE . "', got '{$clientData->getType()}'",
			);
		}

		// §7.1 steps 8–11: challenge, origin and cross-origin policy.
		$this->verifyClientData($clientData, $expectations);

		// §7.1 step 13: decode the attestation object into fmt / authData / attStmt.
		$attestationObject = $response->parseAttestationObject();
		$authData = $attestationObject->parseAuthenticatorData();

		// §7.1 step 14: the authenticator signed over the RP ID we expect.
		$this->verifyRpIdHash($authData, $expectations->rpId);

		// §7.1 step 15: User Present, unless conditional mediation relaxes it.
		if (!$expectations->conditionalMediation && !$authData->isUserPresent()) {
			throw new VerificationException(VerificationException::USER_NOT_PRESENT, 'User Present flag is not set');
		}

		// §7.1 step 16: User Verified, if the RP requires it.
		if ($expectations->requireUserVerification && !$authData->isUserVerified()) {
			throw new VerificationException(VerificationException::USER_NOT_VERIFIED, 'User Verified flag is not set');
		}

		// §7.1 step 17: a credential that is not backup eligible must not be backed up.
		$this->verifyBackupInvariant($authData);

		// A registration response must carry attested credential data (the AT flag / public key).
		$attestedCredentialData = $authData->attestedCredentialData;

		if ($attestedCredentialData === null) {
			throw new VerificationException(
				VerificationException::MISSING_ATTESTED_CREDENTIAL_DATA,
				'Authenticator data does not contain attested credential data',
			);
		}

		// §7.1 step 20: the credential public key uses an algorithm the RP offered.
		$publicKey = $attestedCredentialData->credentialPublicKey;

		if (!in_array($publicKey->alg, $expectations->allowedAlgorithms, true)) {
			throw new VerificationException(
				VerificationException::UNSUPPORTED_ALGORITHM,
				"Credential public key algorithm {$publicKey->alg} is not among the allowed algorithms",
			);
		}

		// §7.1 steps 21–24: verify the attestation statement. `none` carries no statement; `packed`
		// self attestation is verified against the credential public key itself. Formats that need
		// an X.509 trust path are rejected fail-closed until the attestation layer lands.
		$attestationType = $this->verifyAttestationStatement($attestationObject, $publicKey, $response->clientDataJSON);

		// §7.1 step 25: credential ids are bounded at 1023 bytes.
		$credentialId = $attestedCredentialData->credentialId;

		if (strlen($credentialId) > self::MAX_CREDENTIAL_ID_LENGTH) {
			throw new VerificationException(
				VerificationException::CREDENTIAL_ID_TOO_LONG,
				'Credential ID exceeds ' . self::MAX_CREDENTIAL_ID_LENGTH . ' bytes',
			);
		}

		// §7.1 step 26: the credential id must not already be registered for any user.
		if ($store->findByCredentialId($credentialId) !== null) {
			throw new VerificationException(
				VerificationException::CREDENTIAL_ALREADY_REGISTERED,
				'Credential ID is already registered',
			);
		}

		// §7.1 step 27: hand back the record contents for the caller to persist.
		return new RegistrationResult(
			credentialId: $credentialId,
			publicKey: $publicKey,
			signCount: $authData->signCount,
			userVerified: $authData->isUserVerified(),
			backupEligible: $authData->isBackupEligible(),
			backupState: $authData->isBackupState(),
			aaguid: $attestedCredentialData->aaGuid,
			transports: $response->transports,
			attestationType: $attestationType,
		);
	}

	/**
	 * §7.1 steps 21–24, for the statement-less and self-attested cases.
	 *
	 * `none` (§8.7) conveys nothing to verify. `packed` without `x5c` is self attestation (§8.2):
	 * `alg` must match the credential public key's algorithm and `sig` must be a valid signature by
	 * that key over `authData ‖ SHA-256(clientDataJSON)` — clients hand this through unmodified even
	 * under `attestation: "none"` (§5.1.3), so a relying party that ignores attestation still
	 * receives it. Anything needing a certificate trust path stays unsupported.
	 *
	 * @return RegistrationResult::ATTESTATION_*
	 * @throws VerificationException
	 * @throws SignatureVerificationException if the attested credential key cannot be loaded
	 */
	private function verifyAttestationStatement(
		AttestationObject $attestationObject,
		CoseKey $credentialPublicKey,
		string $clientDataJSON,
	): string {
		if ($attestationObject->fmt === self::FMT_NONE) {
			return RegistrationResult::ATTESTATION_NONE;
		}

		if ($attestationObject->fmt !== self::FMT_PACKED || $attestationObject->attStmt->has('x5c')) {
			$detail = $attestationObject->fmt === self::FMT_PACKED ? ' with an x5c certificate chain' : '';

			throw new VerificationException(
				VerificationException::UNSUPPORTED_ATTESTATION_FORMAT,
				"Attestation format '{$attestationObject->fmt}'{$detail} is not supported",
			);
		}

		try {
			$alg = $attestationObject->attStmt->getInt('alg');
			$sig = $attestationObject->attStmt->getString('sig');

		} catch (CborMapException $e) {
			throw new VerificationException(
				VerificationException::INVALID_ATTESTATION_STATEMENT,
				'Malformed packed attestation statement: ' . $e->getMessage(),
				$e,
			);
		}

		if ($alg !== $credentialPublicKey->alg) {
			throw new VerificationException(
				VerificationException::INVALID_ATTESTATION_STATEMENT,
				"Self attestation algorithm {$alg} does not match the credential public key algorithm {$credentialPublicKey->alg}",
			);
		}

		$message = $attestationObject->authData . hash('sha256', $clientDataJSON, binary: true);

		if (!$credentialPublicKey->verify($message, $sig)) {
			throw new VerificationException(
				VerificationException::INVALID_ATTESTATION_STATEMENT,
				'Self attestation signature is invalid',
			);
		}

		return RegistrationResult::ATTESTATION_SELF;
	}

	/**
	 * Verifies an authentication ceremony response (`navigator.credentials.get()`) per WebAuthn §7.2.
	 *
	 * @param  PublicKeyCredential<AuthenticatorAssertionResponse> $credential
	 * @throws VerificationException on any failed §7.2 check, if the response is malformed, or if
	 *     the stored credential key is unusable (unsupported algorithm / cannot be loaded)
	 */
	public function verifyAuthentication(
		PublicKeyCredential $credential,
		AuthenticationExpectations $expectations,
		CredentialStore $store,
	): AuthenticationResult {
		try {
			return $this->doVerifyAuthentication($credential, $expectations, $store);

		} catch (MalformedDataException $e) {
			throw new VerificationException(
				VerificationException::MALFORMED_RESPONSE,
				'Malformed authentication response: ' . $e->getMessage(),
				$e,
			);

		} catch (SignatureVerificationException $e) {
			// A stored key the verifier cannot use is a stored-data fault; surfaced as a distinct
			// reason so it stays distinguishable from a genuine signature mismatch.
			throw new VerificationException(
				VerificationException::UNUSABLE_CREDENTIAL_KEY,
				'Stored credential key is unusable: ' . $e->getMessage(),
				$e,
			);
		}
	}

	/**
	 * @param  PublicKeyCredential<AuthenticatorAssertionResponse> $credential
	 * @throws VerificationException
	 * @throws MalformedDataException
	 * @throws SignatureVerificationException
	 */
	private function doVerifyAuthentication(
		PublicKeyCredential $credential,
		AuthenticationExpectations $expectations,
		CredentialStore $store,
	): AuthenticationResult {
		$response = $credential->response;

		// §7.2 step 5: if allowCredentials was non-empty, the returned credential must be a member.
		if ($expectations->allowedCredentialIds !== null && $expectations->allowedCredentialIds !== []) {
			if (!$this->credentialIdInList($credential->rawId, $expectations->allowedCredentialIds)) {
				throw new VerificationException(
					VerificationException::CREDENTIAL_NOT_ALLOWED,
					'Returned credential is not among the allowed credentials',
				);
			}
		}

		// §7.2 step 6: locate the credential record and resolve the user handle.
		$record = $store->findByCredentialId($credential->rawId);

		if ($record === null) {
			throw new VerificationException(VerificationException::UNKNOWN_CREDENTIAL, 'Credential is not registered');
		}

		$this->verifyUserHandle($response->userHandle, $expectations->expectedUserHandle, $record->userHandle);

		// §7.2 steps 7–10: the client asserts this data was collected for an authentication ceremony.
		$clientData = $response->parseClientData();

		if ($clientData->getType() !== self::TYPE_GET) {
			throw new VerificationException(
				VerificationException::INVALID_CLIENT_DATA_TYPE,
				"Expected client data type '" . self::TYPE_GET . "', got '{$clientData->getType()}'",
			);
		}

		// §7.2 steps 11–14: challenge, origin and cross-origin policy.
		$this->verifyClientData($clientData, $expectations);

		// §7.2 step 15: the authenticator signed over the RP ID we expect.
		$authData = AuthenticatorData::fromBytes($response->authenticatorData);
		$this->verifyRpIdHash($authData, $expectations->rpId);

		// §7.2 step 16: User Present is always required for an assertion.
		if (!$authData->isUserPresent()) {
			throw new VerificationException(VerificationException::USER_NOT_PRESENT, 'User Present flag is not set');
		}

		// §7.2 step 17: User Verified, if the RP requires it.
		if ($expectations->requireUserVerification && !$authData->isUserVerified()) {
			throw new VerificationException(VerificationException::USER_NOT_VERIFIED, 'User Verified flag is not set');
		}

		// §7.2 step 18: a credential that is not backup eligible must not be backed up.
		$this->verifyBackupInvariant($authData);

		// §7.2 step 19: backup eligibility is immutable for a credential.
		if ($authData->isBackupEligible() !== $record->backupEligible) {
			throw new VerificationException(
				VerificationException::BACKUP_ELIGIBILITY_CHANGED,
				'Backup eligibility flag does not match the stored credential record',
			);
		}

		// §7.2 steps 20–21: verify the signature over authenticatorData || SHA-256(clientDataJSON).
		$message = $response->authenticatorData . hash('sha256', $response->clientDataJSON, binary: true);

		if (!$record->publicKey->verify($message, $response->signature)) {
			throw new VerificationException(VerificationException::INVALID_SIGNATURE, 'Assertion signature is invalid');
		}

		// §7.2 step 22: a non-increasing counter is a clone signal, not a hard failure.
		$newSignCount = $authData->signCount;
		$possibleClone = ($newSignCount !== 0 || $record->signCount !== 0) && $newSignCount <= $record->signCount;

		// §7.2 step 24: hand back the new state for the caller to persist.
		return new AuthenticationResult(
			credentialId: $record->credentialId,
			userHandle: $record->userHandle,
			newSignCount: $newSignCount,
			userVerified: $authData->isUserVerified(),
			backupState: $authData->isBackupState(),
			possibleClone: $possibleClone,
		);
	}

	/**
	 * Shared client-data checks: challenge (constant-time), origin allow-list, cross-origin policy,
	 * and top-origin allow-list. Covers §7.1 steps 8–11 and §7.2 steps 11–14.
	 *
	 * @throws VerificationException
	 */
	private function verifyClientData(
		CollectedClientData $clientData,
		RegistrationExpectations|AuthenticationExpectations $expectations,
	): void {
		if (!hash_equals($expectations->challenge, $clientData->getChallenge())) {
			throw new VerificationException(VerificationException::CHALLENGE_MISMATCH, 'Challenge does not match');
		}

		if (!in_array($clientData->getOrigin(), $expectations->origins, true)) {
			throw new VerificationException(
				VerificationException::UNTRUSTED_ORIGIN,
				"Origin '{$clientData->getOrigin()}' is not an expected origin",
			);
		}

		if ($clientData->getCrossOrigin() === true && !$expectations->allowCrossOrigin) {
			throw new VerificationException(
				VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
				'Credential was used cross-origin, which is not allowed',
			);
		}

		// §7.1 step 11 / §7.2 step 14: a present topOrigin means the RP was sub-framed, so cross-origin
		// use must be expected (a) and the embedding page must be one the RP allows (b).
		$topOrigin = $clientData->getTopOrigin();

		if ($topOrigin !== null) {
			if (!$expectations->allowCrossOrigin) {
				throw new VerificationException(
					VerificationException::CROSS_ORIGIN_NOT_ALLOWED,
					'Credential was used in a cross-origin iframe, which is not allowed',
				);
			}

			if (!in_array($topOrigin, $expectations->allowedTopOrigins, true)) {
				throw new VerificationException(
					VerificationException::UNTRUSTED_TOP_ORIGIN,
					"Top origin '{$topOrigin}' is not an expected top origin",
				);
			}
		}
	}

	/**
	 * §7.1 step 14 / §7.2 step 15: the authenticator's RP ID hash must equal SHA-256(expected RP ID).
	 *
	 * @throws VerificationException
	 */
	private function verifyRpIdHash(AuthenticatorData $authData, string $rpId): void
	{
		$expectedHash = hash('sha256', $rpId, binary: true);

		if (!hash_equals($expectedHash, $authData->rpIdHash)) {
			throw new VerificationException(VerificationException::RP_ID_MISMATCH, 'RP ID hash does not match');
		}
	}

	/**
	 * §7.1 step 17 / §7.2 step 18: a credential that is not backup eligible must not report itself
	 * as backed up (¬BE ⇒ ¬BS).
	 *
	 * @throws VerificationException
	 */
	private function verifyBackupInvariant(AuthenticatorData $authData): void
	{
		if (!$authData->isBackupEligible() && $authData->isBackupState()) {
			throw new VerificationException(
				VerificationException::INVALID_BACKUP_STATE,
				'Backup State is set on a credential that is not backup eligible',
			);
		}
	}

	/**
	 * §7.2 step 6: resolve the user handle against the located record.
	 *
	 * When the user was identified before the ceremony ({@see $expectedUserHandle} is set), the
	 * located record — and any handle the authenticator returned — must belong to that user.
	 * Otherwise the ceremony is usernameless: the authenticator must return a handle, and it must
	 * match the record found by credential id.
	 *
	 * @throws VerificationException
	 */
	private function verifyUserHandle(
		?string $responseUserHandle,
		?string $expectedUserHandle,
		string $recordUserHandle,
	): void {
		if ($expectedUserHandle !== null) {
			if (!hash_equals($expectedUserHandle, $recordUserHandle)) {
				throw new VerificationException(
					VerificationException::USER_HANDLE_MISMATCH,
					'Credential does not belong to the identified user',
				);
			}

			if (
				$responseUserHandle !== null
				&& !hash_equals($expectedUserHandle, $responseUserHandle)
			) {
				throw new VerificationException(
					VerificationException::USER_HANDLE_MISMATCH,
					'Returned user handle does not match the identified user',
				);
			}

			return;
		}

		if ($responseUserHandle === null) {
			throw new VerificationException(
				VerificationException::MISSING_USER_HANDLE,
				'User handle is required for a usernameless ceremony',
			);
		}

		if (!hash_equals($responseUserHandle, $recordUserHandle)) {
			throw new VerificationException(
				VerificationException::USER_HANDLE_MISMATCH,
				'Returned user handle does not match the located credential',
			);
		}
	}

	/**
	 * @param  list<string> $list
	 */
	private function credentialIdInList(string $needle, array $list): bool
	{
		foreach ($list as $candidate) {
			if (hash_equals($candidate, $needle)) {
				return true;
			}
		}

		return false;
	}
}
