<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;

/**
 * Where issued authorization codes wait for the token endpoint (architecture §4.4, §4.5). A code is
 * looked up by its hash, never by its value; a used code stays until it expires, so that its replay can
 * be told from an unknown code.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * @param string $codeHash see AuthorizationCode::hash()
     */
    public function findByCodeHash(string $codeHash): ?AuthorizationCode;

    public function save(AuthorizationCode $code): void;
}
