<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;

/**
 * OIDC Core §8 "public", opened: the subject as the core keeps it (decision 0002), which needs nothing from outside
 * the provider, so that opening it reads nothing and assigning it records nothing.
 */
final readonly class OpenedPublicSubjectIdentifier implements OpenedSubjectIdentifierInterface
{
    public function subjectOf(User $user): Subject
    {
        return $user->subject;
    }
}
