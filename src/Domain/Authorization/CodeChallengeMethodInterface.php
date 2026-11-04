<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\Algorithm\NamedAlgorithmInterface;
use SensitiveParameter;

/**
 * RFC 7636 §4.2, §4.3
 *
 * No class answers to "plain": decision 0006 refuses it.
 */
interface CodeChallengeMethodInterface extends NamedAlgorithmInterface
{
    /**
     * RFC 7636 §4.6
     *
     * Compared in constant time; the syntax of the verifier (§4.1) is the caller's to check.
     */
    public function verifies(string $challenge, #[SensitiveParameter] string $codeVerifier): bool;
}
