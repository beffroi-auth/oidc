<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;

interface AssignedSubjectTypesInterface
{
    /**
     * @return non-empty-list<non-empty-string> the first is the kind a client that registers none takes
     */
    public function assignedSubjectTypes(): array;

    /**
     * @throws UnreadableClientMetadataException
     */
    public function assertAssignable(ClientRegistration $registration): void;
}
