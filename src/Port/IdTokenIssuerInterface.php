<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use DateTimeImmutable;
use Beffroi\Oidc\Domain\Token\AccessToken;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;

/**
 * Mints the ID token of a response (OIDC Core §2, architecture §4.6); the access token is given for "at_hash".
 *
 * An ID token describes who signed in, so it is issued from an authorization somebody signed in for and
 * from no other: a grant with nobody behind it has none to carry (RFC 6749 §4.4.3).
 */
interface IdTokenIssuerInterface
{
    /**
     * @return string the compact JWS
     */
    public function issue(UserAuthorizationInterface $authorization, AccessToken $accessToken, DateTimeImmutable $now): string;
}
