<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §3.2.2 "invalid_software_statement": the statement the registration carries does not verify.
 *
 * It reads the same whatever gave it away, a value that is no compact JWS, an "iss" this tenant pinned
 * nobody by, a signature that does not verify under the keys it pinned, an algorithm it does not sign
 * with, a statement addressed elsewhere, expired, not yet issued, or replayed: whoever does not hold a
 * key this tenant pinned learns nothing about the one they signed with (decision 0006). That is one
 * refusal, so it is written once here and never beside each check.
 *
 * §3.2.2 offers a second code for a statement of its own, "unapproved_software_statement", for one that
 * verifies and is not accepted all the same. Nothing here answers with it, and nothing here can: what a
 * verified statement names that the tenant does not offer is answered "invalid_client_metadata" by the
 * rule and the code path that answer a request body naming it, its members saying what the client **is**
 * while the policy says what it **may have**; and every other way a statement is refused is a way it
 * failed to verify. Telling the two apart would say which half a presenter got right, which is the one
 * thing decision 0006 keeps this refusal from saying.
 */
final class InvalidSoftwareStatementException extends UnreadableClientMetadataException
{
    /**
     * The one thing a caller is told, whatever went wrong.
     */
    private const string REFUSED = 'The software_statement is not one this tenant accepts (RFC 7591 section 2.3).';

    public function __construct(?string $source = null, ?Throwable $previous = null)
    {
        parent::__construct('invalid_software_statement', 'software_statement', $source, self::REFUSED, $previous);
    }
}
