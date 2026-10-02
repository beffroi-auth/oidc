<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Authorization\CodeChallengeMethodInterface;

/**
 * The PKCE methods the wiring gives the provider (RFC 7636 §4.2), the one source of truth over them: what
 * "code_challenge_methods_supported" announces, what an authorization request may name in
 * "code_challenge_method" and what a stored challenge is read back as all read this one, so that they
 * cannot disagree.
 */
interface CodeChallengeMethodsInterface
{
    /**
     * @return non-empty-list<CodeChallengeMethodInterface> in the order they are wired
     */
    public function codeChallengeMethods(): array;

    /**
     * Null when the provider is wired with no method of that name, the caller wording its own refusal: an
     * authorization request that names one is refused to the client, a stored challenge that names one is
     * a row this deployment cannot account for.
     */
    public function codeChallengeMethodNamed(string $name): ?CodeChallengeMethodInterface;
}
