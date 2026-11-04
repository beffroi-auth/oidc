<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;

interface CodeChallengeMethodsInterface
{
    /**
     * @return non-empty-list<CodeChallengeMethodInterface>
     */
    public function codeChallengeMethods(): array;

    public function codeChallengeMethodNamed(string $name): ?CodeChallengeMethodInterface;
}
