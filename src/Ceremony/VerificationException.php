<?php declare(strict_types = 1);

namespace WebAuthnX\Ceremony;

use RuntimeException;
use Throwable;

/**
 * Thrown when a registration or authentication ceremony fails any WebAuthn §7.1 / §7.2 check.
 *
 * The library is fail-closed: a caller that receives a {@see RegistrationResult} /
 * {@see AuthenticationResult} instead of this exception knows every mandated check passed. A
 * structurally malformed response (bad JSON/CBOR/base64url/COSE) is reported here too, as
 * {@see self::MALFORMED_RESPONSE}, so a single catch of this type covers every failure mode.
 * The {@see $reason} carries a stable, machine-readable code (one of the `self::*` constants)
 * so callers can branch on the failure without parsing the human-readable message.
 *
 * The reason codes are diagnostic: a relying party should not echo them verbatim to end users,
 * as the distinction between e.g. {@see self::USER_HANDLE_MISMATCH} and
 * {@see self::INVALID_SIGNATURE} can leak whether a credential belongs to a given account.
 *
 * @api
 */
final class VerificationException extends RuntimeException
{
	public const MALFORMED_RESPONSE = 'malformed_response';
	public const INVALID_CLIENT_DATA_TYPE = 'invalid_client_data_type';
	public const CHALLENGE_MISMATCH = 'challenge_mismatch';
	public const UNTRUSTED_ORIGIN = 'untrusted_origin';
	public const UNTRUSTED_TOP_ORIGIN = 'untrusted_top_origin';
	public const CROSS_ORIGIN_NOT_ALLOWED = 'cross_origin_not_allowed';
	public const RP_ID_MISMATCH = 'rp_id_mismatch';
	public const USER_NOT_PRESENT = 'user_not_present';
	public const USER_NOT_VERIFIED = 'user_not_verified';
	public const INVALID_BACKUP_STATE = 'invalid_backup_state';
	public const UNSUPPORTED_ATTESTATION_FORMAT = 'unsupported_attestation_format';
	public const MISSING_ATTESTED_CREDENTIAL_DATA = 'missing_attested_credential_data';
	public const UNSUPPORTED_ALGORITHM = 'unsupported_algorithm';
	public const CREDENTIAL_ID_TOO_LONG = 'credential_id_too_long';
	public const CREDENTIAL_ALREADY_REGISTERED = 'credential_already_registered';
	public const CREDENTIAL_NOT_ALLOWED = 'credential_not_allowed';
	public const UNKNOWN_CREDENTIAL = 'unknown_credential';
	public const MISSING_USER_HANDLE = 'missing_user_handle';
	public const USER_HANDLE_MISMATCH = 'user_handle_mismatch';
	public const BACKUP_ELIGIBILITY_CHANGED = 'backup_eligibility_changed';
	public const INVALID_SIGNATURE = 'invalid_signature';
	public const UNUSABLE_CREDENTIAL_KEY = 'unusable_credential_key';

	/**
	 * @param  self::* $reason
	 */
	public function __construct(
		public readonly string $reason,
		string $message,
		?Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}
}
