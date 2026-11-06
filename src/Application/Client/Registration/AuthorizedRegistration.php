<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadataSourceInterface;
use Beffroi\Oidc\Domain\Client\Metadata\GrantedMembers;

/**
 * What a mode of registration answers once it authorised a registration (decision 0009): what it puts in front of the
 * members the client sent, and what the tenant gives the client beside them (decision 0043).
 */
final readonly class AuthorizedRegistration
{
    /**
     * @param list<ClientMetadataSourceInterface> $inFront in the order they win; empty for a mode that reads none
     */
    public function __construct(
        public array $inFront = [],
        public ?GrantedMembers $granted = null,
    ) {
    }
}
