<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;

/**
 * What a response carries beyond its scopes (RFC 9396 §2, §7), asked of an authorization of any kind: the
 * details of one somebody signed in for, and none of one nobody was asked for.
 *
 * Only an authorization somebody signed in for carries details (`UserAuthorizationInterface`), because a
 * detail is what a user agreed to; the reading is named here because two things need it and neither owns it,
 * the self-contained access token writing it as a claim and the token response saying what it granted. Written
 * once rather than at each of the two, as the digests of the tokens an event revoked are (RevokedTokenHashes).
 */
final readonly class CarriedAuthorizationDetails
{
    public static function of(AuthorizationInterface $authorization): ?AuthorizationDetails
    {
        return $authorization instanceof UserAuthorizationInterface ? $authorization->authorizationDetails : null;
    }
}
