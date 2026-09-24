<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7636 §4.2 and decision 0006: the one method this provider accepts. "plain" is not wired anywhere,
 * so it is not announced anywhere.
 */
final readonly class AnnouncedPkce implements MetadataContributorInterface
{
    public function metadata(Tenant $tenant): array
    {
        return [
            'code_challenge_methods_supported' => array_map(
                static fn (CodeChallengeMethod $method): string => $method->value,
                CodeChallengeMethod::cases(),
            ),
        ];
    }
}
