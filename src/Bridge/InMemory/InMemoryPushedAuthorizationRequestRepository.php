<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use DateTimeImmutable;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRequest;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;

/**
 * For tests and for the examples: nothing here survives the process, and one process claims a record
 * once because nothing else runs beside it.
 */
final class InMemoryPushedAuthorizationRequestRepository implements PushedAuthorizationRequestRepositoryInterface
{
    /**
     * @var array<string, PushedAuthorizationRequest> by request URI hash
     */
    private array $requests = [];

    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRequest
    {
        return $this->requests[$requestUriHash] ?? null;
    }

    public function consume(PushedAuthorizationRequest $request, DateTimeImmutable $now): bool
    {
        $stored = $this->requests[$request->requestUriHash] ?? null;
        if ($stored === null || $stored->isUsed()) {
            return false;
        }
        $stored->consume($now);

        return true;
    }

    public function save(PushedAuthorizationRequest $request): void
    {
        $this->requests[$request->requestUriHash] = $request;
    }
}
