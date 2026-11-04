<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Throwable;

/**
 * RFC 7591 §3.2.2
 *
 * One refusal whatever gave it away, and never "unapproved_software_statement": telling the two apart would say
 * which half a presenter got right (decision 0006).
 */
final class InvalidSoftwareStatementException extends UnreadableClientMetadataException
{
    private const string REFUSED = 'The software_statement is not one this tenant accepts (RFC 7591 section 2.3).';

    public function __construct(?string $source = null, ?Throwable $previous = null)
    {
        parent::__construct('invalid_software_statement', 'software_statement', $source, self::REFUSED, $previous);
    }
}
