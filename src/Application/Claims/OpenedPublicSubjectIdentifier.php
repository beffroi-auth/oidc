<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;

/**
 * OIDC Core §8
 */
final readonly class OpenedPublicSubjectIdentifier implements OpenedSubjectIdentifierInterface
{
    public function subjectOf(User $user): Subject
    {
        return $user->subject;
    }
}
