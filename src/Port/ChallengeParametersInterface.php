<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

/**
 * What the challenge of a protected resource of this provider says of a scheme whatever the refusal
 * (RFC 9110 §11.6.1): what a client needs to present a token under that scheme, which RFC 9449 §7.1 gives
 * the DPoP scheme in "algs", the algorithms a proof may be signed with.
 *
 * It is derived from what the provider is wired with and never listed beside it, as the schemes themselves
 * are (`ServedTokenSchemesInterface`).
 */
interface ChallengeParametersInterface
{
    /**
     * @return array<non-empty-string, array<non-empty-string, non-empty-string>> the auth-params of the
     *                                                                            challenge of each scheme
     *                                                                            that defines some, by
     *                                                                            scheme as this provider
     *                                                                            spells it
     */
    public function challengeParameters(): array;
}
