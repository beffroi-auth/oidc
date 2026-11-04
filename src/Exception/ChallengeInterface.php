<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * RFC 6750 §3, RFC 9449 §7.1
 */
interface ChallengeInterface extends ExceptionInterface
{
    /**
     * @return non-empty-string
     */
    public function challengeScheme(): string;

    /**
     * @return array<string, string> header values by name
     */
    public function challengeHeaders(): array;
}
