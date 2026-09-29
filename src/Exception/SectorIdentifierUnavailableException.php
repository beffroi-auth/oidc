<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use RuntimeException as BaseRuntimeException;

/**
 * The document behind a "sector_identifier_uri" could not be read back: the client answered an error,
 * answered too slowly, answered too much, redirected (decision 0006: no outbound redirect is followed) or
 * answered something that is not the JSON array of redirection URIs OIDC Registration §5 asks for.
 *
 * It is raised where the document is fetched and answered where a registration is refused: a client whose
 * sector cannot be verified registers no sector.
 */
final class SectorIdentifierUnavailableException extends BaseRuntimeException implements ExceptionInterface
{
}
