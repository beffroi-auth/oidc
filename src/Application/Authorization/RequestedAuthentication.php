<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Authorization\RequestedAuthenticationContext;

/**
 * What a request demands of the authentication, read before any login (architecture §4.3): the rules of a
 * requested "acr" (decision 0010), and the "sub" an "id_token_hint" carries.
 *
 * Both are established before a session is looked at, and for the same reason: an essential "acr" this provider
 * can prove none of, and a hint whose signature is not ours, are refusals the user could do nothing about on a
 * page, so no page is shown for them (OIDC Core §3.1.2.1, §5.5.1.1).
 */
final readonly class RequestedAuthentication
{
    /**
     * @param Subject|null $hinted the "sub" the "id_token_hint" carries, as the client of the request was given
     *                           it (OIDC Core §8), null when the request carries none
     */
    public function __construct(
        public RequestedAuthenticationContext $context,
        public ?Subject $hinted,
    ) {
    }
}
