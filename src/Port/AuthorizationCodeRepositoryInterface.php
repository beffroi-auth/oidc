<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Symfony\Component\Uid\Uuid;

/**
 * Where issued authorization codes wait for the token endpoint (architecture §4.4, §4.5). A code is
 * looked up by its hash, never by its value; a used code stays, so that its replay can be told from an
 * unknown code.
 *
 * The record is also the grant, which a protected resource of the provider looks up by the opaque name
 * the access tokens carry, to learn whether the replay of the code revoked it (RFC 6749 §4.1.2). That
 * is what its retention answers to: a record is kept as long as a token descending from it may still be
 * presented, the lifetime of the refresh token family and not the sixty seconds of the code.
 */
interface AuthorizationCodeRepositoryInterface
{
    /**
     * @param string $codeHash see AuthorizationCode::hash()
     */
    public function findByCodeHash(string $codeHash): ?AuthorizationCode;

    /**
     * The code the access tokens of that grant descend from, whatever its state.
     */
    public function findByGrantId(Uuid $grantId): ?AuthorizationCode;

    public function save(AuthorizationCode $code): void;
}
