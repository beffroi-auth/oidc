<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Event;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Event\DomainEventInterface;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\RefreshToken;

/**
 * An authorization code was presented a second time (RFC 6749 §4.1.2); the tokens issued from it are revoked.
 */
final readonly class AuthorizationCodeReplayed implements DomainEventInterface
{
    /**
     * @param string $presentedBy not necessarily the client the code was issued to
     * @param list<string> $revokedTokenHashes
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $codeHash,
        public string $issuedTo,
        public string $presentedBy,
        public array $revokedTokenHashes,
        public RequestContext $context,
    ) {
    }

    /**
     * @param list<RefreshToken> $revoked
     */
    public static function of(DateTimeImmutable $occurredAt, AuthorizationCode $code, Client $presentedBy, array $revoked, RequestContext $context): self
    {
        return new self(
            $occurredAt,
            $code->tenant,
            $code->codeHash,
            $code->clientId,
            $presentedBy->registration->clientId,
            array_map(static fn (RefreshToken $token): string => $token->tokenHash, $revoked),
            $context,
        );
    }
}
