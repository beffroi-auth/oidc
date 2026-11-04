<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery\Metadata;

use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\ResponseModeNames;
use Beffroi\Oidc\Domain\Authorization\ResponseTypeNames;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Port\ServedResponseModesInterface;

/**
 * OIDC Discovery §3, Multiple Response Type Encoding Practices §2.1, JARM §2.1
 */
final readonly class AnnouncedResponses implements MetadataContributorInterface
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $modes = array_values(array_unique($this->responseModes->servedResponseModes()));

        return [
            'response_types_supported' => [ResponseTypeNames::CODE],
            'response_modes_supported' => $this->responseModes->signsAnyAnswer() ? [...$modes, ResponseModeNames::ALIAS] : $modes,
        ];
    }
}
