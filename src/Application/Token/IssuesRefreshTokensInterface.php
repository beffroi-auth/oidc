<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

/**
 * A grant whose response may carry a refresh token (RFC 6749 §4.1.4, §5.1). It carries nothing else:
 * that a response of this grant can hold one is the whole of what the rest of the provider reads here,
 * and when it holds one is the grant's own decision.
 */
interface IssuesRefreshTokensInterface extends GrantInterface
{
}
