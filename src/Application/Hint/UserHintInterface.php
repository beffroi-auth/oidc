<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\OAuth2Exception;
use SensitiveParameter;

/**
 * One way a request may name the user it is made for, whichever side of the provider it arrives on: the
 * authorization request a browser carries (OIDC Core §3.1.2.1) and the backchannel authentication request
 * a client makes (CIBA Core §7.1) carry the same "login_hint", and this provider reads it one way. One
 * class per way, wired into the provider: what a request of this tenant may name its user by is what is
 * wired, and a hint the provider gains is a class added rather than a case read somewhere.
 *
 * This is what §7.1 asks to be "a rule of the tenant" rather than a search: a hint is read by exactly one
 * of these, which knows what that value is and looks the user up by it, and never by whichever lookup
 * happens to match something.
 */
interface UserHintInterface
{
    /**
     * The name of the parameter this hint arrives in, which is what the composite of each side picks a
     * reading by: one of the three CIBA Core §7.1 names on the backchannel side, "login_hint" on the
     * authorization one.
     */
    public function parameterName(): string;

    /**
     * The user this hint names, null when it names nobody. Naming nobody is not an error and is never
     * told apart from naming somebody who does not answer (decision 0006).
     *
     * @throws OAuth2Exception when the value is not of the shape this hint reads at all, which says
     *                         nothing about any user
     */
    public function userNamedBy(Client $client, #[SensitiveParameter] string $value): ?User;
}
