<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;

/**
 * The user a "sub" names, read back **for the client that presented it** (OIDC Core §8): the way in of what
 * SubjectIdentifierResolverInterface is the way out.
 *
 * It is a port and not a lookup by row key because a "sub" is not one: under a pairwise kind (§8.1) the
 * string a client holds is the one that client sees and no row carries it, so reading it as an identifier of
 * the provider would find nobody. What it means is only ever decided by the kind the client registered, which
 * is what makes a "sub" of one client presented by another name nobody, the property pairwise exists for.
 */
interface PresentedSubjectReaderInterface
{
    /**
     * Null when no user of that client's tenant answers to that "sub" under the kind that client registered.
     */
    public function findUser(Client $client, Subject $subject): ?User;
}
