<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Consent;

use Beffroi\Core\Domain\Listing\Period;
use Beffroi\Oidc\Domain\Scope\Scope;
use function in_array;
use function mb_stripos;

/**
 * What a list of consents is narrowed to, a criterion left null admitting every consent.
 */
final readonly class ConsentQuestion
{
    /**
     * @param string|null $claim a claim it grants by name (OIDC Core §5.5)
     * @param string|null $detailType a type of the authorization details it grants (RFC 9396 §2)
     * @param string|null $applicationName what the name the application presents contains, whatever the case
     */
    public function __construct(
        public ?Period $granted = null,
        public ?Scope $scope = null,
        public ?string $claim = null,
        public ?string $detailType = null,
        public ?string $applicationName = null,
    ) {
    }

    public function admits(Consent $consent): bool
    {
        return (
            $this->granted?->holds($consent->grantedAt) !== false
            && ($this->scope === null || $consent->scopes->has($this->scope))
            && ($this->claim === null || $consent->claims->has($this->claim))
            && ($this->detailType === null || in_array($this->detailType, $consent->authorizationDetails?->types() ?? [], true))
            && ($this->applicationName === null || mb_stripos($consent->client->registration->presentation->name, $this->applicationName) !== false)
        );
    }
}
