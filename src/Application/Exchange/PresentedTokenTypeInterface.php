<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Exchange;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidRequestException;
use SensitiveParameter;

/**
 * RFC 8693 §3
 */
interface PresentedTokenTypeInterface
{
    public function identifier(): TokenTypeIdentifier;

    /**
     * @throws InvalidRequestException for every token it refuses, whatever the reason (RFC 8693 §2.2.2)
     */
    public function read(Tenant $tenant, #[SensitiveParameter] string $token, DateTimeImmutable $now): PresentedToken;
}
