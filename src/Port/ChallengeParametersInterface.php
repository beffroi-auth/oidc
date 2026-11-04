<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

/**
 * RFC 9110 §11.6.1, RFC 9449 §7.1
 */
interface ChallengeParametersInterface
{
    /**
     * @return array<non-empty-string, array<non-empty-string, non-empty-string>> auth-params by scheme
     */
    public function challengeParameters(): array;
}
