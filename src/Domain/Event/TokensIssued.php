<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * The token endpoint answered a client. The event says what was authorized and what kind of tokens
 * left, never their values: the access token and the ID token are not stored anywhere, the refresh
 * token is named by its record.
 */
final readonly class TokensIssued implements DomainEventInterface
{
    public Tenant $tenant;

    /**
     * @param RefreshToken|null $refreshToken the record of the refresh token issued, if one was
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public GrantedAuthorization $authorization,
        public DateTimeImmutable $accessTokenExpiresAt,
        public bool $idTokenIssued,
        public ?RefreshToken $refreshToken,
        public RequestContext $context,
    ) {
        $this->tenant = $authorization->tenant;
    }
}
