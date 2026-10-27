<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Exception\LogicException;

/**
 * The kind of "sub" one client registered, opened for that client (OIDC Core §8): what assigning its identifiers
 * needs from outside the provider read already, the salt of its tenant for a pairwise client (§8.1) and nothing for
 * a public one, so that the "sub" of a user is then assigned asking nothing of the KMS. It is the second half of
 * an assignment in two steps (SubjectIdentifierOpenerInterface), the one a caller that has spent what it cannot
 * get back still runs.
 */
interface OpenedSubjectIdentifierInterface
{
    /**
     * The identifier the client sees for that user, recorded where the kind records what it assigned.
     *
     * @throws LogicException when the user is not of the tenant whose secret was opened
     */
    public function subjectOf(User $user): Subject;
}
