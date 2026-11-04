<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Exchange\Actor;

/**
 * An authorization whose subject was named by what the client presented, not by a session of this provider.
 */
interface NamesItsSubjectInterface extends AuthorizationInterface
{
    public Subject $subject { get; }

    public ?TokenSignIn $signIn { get; }

    public ?Actor $actor { get; }
}
