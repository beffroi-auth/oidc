<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

/**
 * A client authentication method as the endpoints run it: the name it answers to, whether the request
 * carries what it needs, and the proof it verifies or the refusal it raises. One class per method, wired
 * into the provider; the authenticator picks the one the client registered and knows nothing of what any
 * of them reads.
 */
interface AuthenticationMethodInterface extends ClientAuthenticationMethodInterface
{
    /**
     * What of the request this method reads, one of the names ClientAuthenticationRequest gives them.
     * Two methods that read the same thing are one mechanism of RFC 6749 §2.3, whichever of them a
     * client registered; two methods that read different things are two, and a request presenting both
     * is refused.
     *
     * @return non-empty-string
     */
    public function mechanism(): string;

    /**
     * The identifier the request claims under this method, null when the request does not present this
     * method at all.
     *
     * @throws ClientAuthenticationFailure when the request presents this method and presents it wrongly
     */
    public function presentedBy(ClientAuthenticationRequest $request): ?string;

    /**
     * @throws ClientAuthenticationFailure when the proof the request carries is not the client's
     */
    public function verify(ClientAuthenticationRequest $request, Client $client): void;

    /**
     * What a refusal costs when there is nothing to verify against: an unknown client, or a client
     * registered for another method. A refusal takes the time an acceptance takes, so that it says
     * nothing about who is registered (decision 0006).
     */
    public function payRefusal(ClientAuthenticationRequest $request): void;
}
