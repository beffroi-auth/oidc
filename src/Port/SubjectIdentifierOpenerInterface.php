<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * A caller that spends what it cannot get back opens before it spends, so that an outage of the KMS costs it
 * nothing; assigning from what was opened asks nothing of the KMS.
 */
interface SubjectIdentifierOpenerInterface
{
    /**
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind this client registered, or
     *                                  the client names no sector a pairwise identifier is computed per
     * @throws KmsUnavailableException
     * @throws RuntimeException when the salt can neither be read nor drawn
     */
    public function open(Client $client): OpenedSubjectIdentifierInterface;
}
