<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * A refusal that says how the request should have been made: the scheme a protected resource names in
 * its challenge (RFC 6750 §3, RFC 9449 §7.1), which is the one that would have worked and not always
 * the one the request used, and whatever the refusal carries beside it, at a resource as at an endpoint
 * that issues tokens (RFC 9449 §8).
 *
 * The same failure is not worth the same everywhere: a proof a token endpoint refuses with a 400 and a
 * JSON body (RFC 9449 §5) a resource refuses with a 401 and this challenge (§7.1).
 */
interface ChallengeInterface extends ExceptionInterface
{
    /**
     * @return non-empty-string the authentication scheme of the challenge
     */
    public function challengeScheme(): string;

    /**
     * @return array<string, string> what the refusal carries beside the challenge, the nonce of
     *                               RFC 9449 §8 and nothing else today
     */
    public function challengeHeaders(): array;
}
