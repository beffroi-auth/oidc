<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Port\CodeChallengeMethodsInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7636 §4.2
 */
final readonly class AnnouncedPkce implements MetadataContributorInterface
{
    public function __construct(
        private CodeChallengeMethodsInterface $methods,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        return [
            'code_challenge_methods_supported' => AlgorithmNames::of($this->methods->codeChallengeMethods()),
        ];
    }
}
