<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Key\AlgorithmNames;
use Heidi\Oidc\Port\CodeChallengeMethodsInterface;
use Heidi\Oidc\Port\MetadataContributorInterface;

/**
 * RFC 7636 §4.2: the methods the provider is wired to verify a challenge with, read from the wiring and
 * never enumerated here. "plain" is wired nowhere, decision 0006 refusing it, so it is announced nowhere.
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
