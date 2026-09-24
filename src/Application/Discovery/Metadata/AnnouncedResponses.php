<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery\Metadata;

use function array_any;
use function array_unique;
use function array_values;
use const SORT_REGULAR;
use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Port\MetadataContributorInterface;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * OIDC Discovery §3 and Multiple Response Type Encoding Practices §2.1: the one response type this
 * provider serves, and the modes the integration wired. JARM §2.1 adds "jwt", which delivers nothing of
 * its own and names the signed mode a response type defaults to: it is announced because a signed mode
 * is wired, never because it is listed somewhere.
 */
final readonly class AnnouncedResponses implements MetadataContributorInterface
{
    public function __construct(
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    public function metadata(Tenant $tenant): array
    {
        $modes = array_values(array_unique($this->responseModes->servedResponseModes(), SORT_REGULAR));
        $signs = array_any($modes, static fn (ResponseMode $mode): bool => $mode->signsTheAnswer());

        return [
            'response_types_supported' => ['code'],
            'response_modes_supported' => array_map(
                static fn (ResponseMode $mode): string => $mode->value,
                $signs ? [...$modes, ResponseMode::Jwt] : $modes,
            ),
        ];
    }
}
