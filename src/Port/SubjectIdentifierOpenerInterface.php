<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * What assigns a "sub" in two steps (OIDC Core §8): the kind the client registered opened first, which is the step
 * that can fail on a KMS that does not answer, and the "sub" of a user assigned afterwards from what was opened,
 * which asks nothing of the KMS. A caller that spends what it cannot get back opens before it spends, so that an
 * outage of the KMS costs it nothing (architecture §4.5); a caller that spends nothing resolves in one step
 * (SubjectIdentifierResolverInterface).
 */
interface SubjectIdentifierOpenerInterface
{
    /**
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind this client registered,
     *                                  or the client names no sector a pairwise identifier is computed per
     * @throws KmsUnavailableException when the KMS of the tenant does not answer to open the salt its pairwise identifiers are computed with
     * @throws RuntimeException when that salt can neither be read nor drawn
     */
    public function open(Client $client): OpenedSubjectIdentifierInterface;
}
