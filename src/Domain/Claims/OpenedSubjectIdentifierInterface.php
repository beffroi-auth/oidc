<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Exception\LogicException;

/**
 * OIDC Core §8
 *
 * Asks nothing of the KMS, so that a caller may run it after spending what it cannot get back.
 */
interface OpenedSubjectIdentifierInterface
{
    /**
     * Records what it assigns, where the kind records it.
     *
     * @throws LogicException when the user is not of the tenant whose secret was opened
     */
    public function subjectOf(User $user): Subject;
}
