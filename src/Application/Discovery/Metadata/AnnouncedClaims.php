<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function in_array;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClaimsProviderInterface;
use Beffroi\Oidc\Port\MetadataContributorInterface;

/**
 * OIDC Discovery §3
 */
final readonly class AnnouncedClaims implements MetadataContributorInterface
{
    public function __construct(
        private ClaimsProviderInterface $claims,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $claims = ['sub'];
        foreach ($this->claims->supportedClaims() as $claim) {
            if ($claim === '') {
                throw new InvalidArgumentException('A supported claim has a name.');
            }
            if (! in_array($claim, $claims, true)) {
                $claims[] = $claim;
            }
        }

        return [
            'claims_supported' => $claims,
            'claims_parameter_supported' => true,
        ];
    }
}
