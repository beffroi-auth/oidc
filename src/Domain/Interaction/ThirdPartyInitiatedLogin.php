<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * Where a browser goes when this provider begins a login at a client (OIDC Core §4): the
 * "initiate_login_uri" that client registered, carrying the issuer of this provider so the client knows
 * which provider to have its user authenticate against. What the client does next is the ordinary
 * authorization request, and from there the flow is the one this provider already answers.
 *
 * It is the one place this provider sends a browser somewhere nobody asked it to come back from. So
 * everything the redirection carries comes from the registration of that client or from this provider,
 * and nothing from the request that asked for it: a destination read from a query string would make this
 * provider a redirector for whoever found the route, and a "target_link_uri" forwarded from one would
 * make it a redirector with a landing page of the caller's choosing. The rule holds by what this takes
 * rather than by what it checks, which is why the destination is the InitiateLoginUri the client registered
 * and the landing page the RedirectUri it registered, both objects and neither a string.
 */
final readonly class ThirdPartyInitiatedLogin
{
    /**
     * What is added to the registered URI, in the names of OIDC Core §4.
     *
     * @var non-empty-array<non-empty-string, string>
     */
    public array $parameters;

    /**
     * @param Subject|null $loginHint whom to sign in, as this client sees them (OIDC Core §8), so that a
     *                                pairwise client is not handed the one string pairwise withholds;
     *                                null when no browser session says who is asking, which is the
     *                                ordinary case for a login nobody has begun yet
     * @param RedirectUri|null $targetLinkUri where the client is asked to land the user once it has
     *                                        signed them in; null unless the request named one this
     *                                        client registered
     */
    public function __construct(
        public InitiateLoginUri $initiateLoginUri,
        public Issuer $issuer,
        public ?Subject $loginHint = null,
        public ?RedirectUri $targetLinkUri = null,
    ) {
        $parameters = [
            'iss' => $issuer->value,
        ];
        if ($loginHint !== null) {
            $parameters['login_hint'] = $loginHint->value;
        }
        if ($targetLinkUri !== null) {
            $parameters['target_link_uri'] = $targetLinkUri->value;
        }
        $this->parameters = $parameters;
    }

    /**
     * The query the client registered is kept and these are added to it (InitiateLoginUri::withParameters): a
     * client that registered an "initiate_login_uri" with a query of its own is sent to the URI it
     * registered, not to a rewriting of it.
     */
    public function location(): string
    {
        return $this->initiateLoginUri->withParameters($this->parameters);
    }
}
