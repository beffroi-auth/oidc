<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

/**
 * A refusal a protected resource answers with a challenge, and the scheme that challenge names (RFC 6750 §3,
 * RFC 9449 §7.1): the one the request presented its token under, whose challenge delivers the error
 * (RFC 9449 §7.2), save for a refusal of the proof, which names the scheme of the proof, and a refusal of
 * how the token was presented, which names the one that would have worked; and whatever the refusal
 * carries beside it, at a resource as at an endpoint that issues tokens (RFC 9449 §8).
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
