<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use DateTimeImmutable;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\StoredAccessToken;
use SensitiveParameter;

/**
 * Where the access tokens the provider keeps live while they may be presented (architecture §4.6): the
 * opaque ones today, whose value is a reference to a record, and the one place that draws such a value
 * and hashes it (OpaqueTokenValue). The value exists outside the client for the time of the response
 * that carries it, the store keeps the hash. A self-contained token lives nowhere and never comes here.
 *
 * What else a store can do is declared by the companion interfaces it implements, CanRevokeAccessTokenInterface
 * and the two bulk ones: the callers ask, and a store that cannot revoke is a store whose tokens expire on
 * their own. Expired records are for a sweep to remove.
 */
interface AccessTokenRepositoryInterface
{
    /**
     * Draws a value, keeps its record, returns the value for the response and nothing else.
     */
    public function issue(GrantedAuthorization $authorization, DateTimeImmutable $now, DateTimeImmutable $expiresAt): string;

    /**
     * @param string $token the value as the client presents it
     */
    public function find(#[SensitiveParameter] string $token): ?StoredAccessToken;
}
