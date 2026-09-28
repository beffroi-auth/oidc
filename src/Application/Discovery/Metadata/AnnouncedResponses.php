<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_unique;
use function array_values;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\ResponseModeNames;
use Heidi\Oidc\Domain\Authorization\ResponseType;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * OIDC Discovery §3 and Multiple Response Type Encoding Practices §2.1: the one response type this
 * provider answers at all (ResponseType), and the modes the integration wired, under the names the ways of
 * answering give themselves. JARM §2.1 adds "jwt", which delivers nothing of its own and names the signed mode a
 * response type defaults to: it is announced because a signed mode is wired, never because it is listed
 * somewhere.
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
            'response_types_supported' => ResponseType::names(),
            'response_modes_supported' => $this->responseModes->signsAnyAnswer() ? [...$modes, ResponseModeNames::ALIAS] : $modes,
        ];
    }
}
