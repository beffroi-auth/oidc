<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\AdministrationResourceInterface;
use function sprintf;

/**
 * The administration API of the tenant a deployment declares (decision 0038), by the identifier the deployment names,
 * read once, when this service is built: a value that is not an absolute URI without a fragment (RFC 8707 §2) refuses
 * that construction. Asked about another tenant, this answers as a tenant whose deployment names none.
 */
final readonly class ConfigurationAdministrationResource implements AdministrationResourceInterface
{
    private ?ResourceIndicator $resource;

    /**
     * @param string|null $resource the identifier, null for a deployment that names none
     *
     * @throws InvalidArgumentException when the identifier is not an absolute URI, or carries a fragment
     */
    public function __construct(
        private string $tenantSlug,
        ?string $resource = null,
    ) {
        try {
            $this->resource = $resource === null ? null : new ResourceIndicator($resource);
        } catch (InvalidArgumentException $refusal) {
            throw new InvalidArgumentException(
                sprintf(
                    'The administration API of the tenant "%s" is named by an identifier that is no resource identifier: %s',
                    $this->tenantSlug,
                    $refusal->getMessage(),
                ),
                0,
                $refusal,
            );
        }
    }

    public function administrationResourceOf(Tenant $tenant): ?ResourceIndicator
    {
        return $tenant->slug === $this->tenantSlug ? $this->resource : null;
    }
}
