<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Administration\Administrators;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\UserAuthorizationInterface;
use Beffroi\Oidc\Exception\AccessDeniedException;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Port\AdministrationResourceInterface;

/**
 * The audience of the administration API of a tenant, which the provider reserves to the administrators of that tenant
 * (decision 0038). A token is addressed to it only for a person who administers the tenant when the token is minted,
 * read from the groups of that person, signed in at the authorization endpoint by a session whose proofs satisfy
 * phishing_resistant whatever the floor of the tenant, and bound to a key of the client. A tenant whose deployment
 * names no administration API reserves nothing.
 *
 * The authorization endpoint asks for that proof and turns away whoever does not administer the tenant, which is what
 * the person sees; the grants that start elsewhere never hand it out; and the issuance of every access token holds to
 * the whole of it, so that a grant added later is held to it without knowing of it.
 */
final readonly class AdministrationAudience
{
    private const string NOT_AN_ADMINISTRATOR = 'The end user does not administer the tenant whose administration API the request names.';

    public function __construct(
        private AdministrationResourceInterface $resources,
        private Administrators $administrators,
    ) {
    }

    /**
     * OIDC Core §5.5.1.1: what a request asks of the authentication. One that names the administration API of its
     * tenant demands "phr", essential, in place of whatever it asked for itself, and whatever the floor of the tenant:
     * a session that does not satisfy it is stepped up, and a person who holds no credential able to satisfy it is
     * turned away before any page.
     */
    public function authenticationAskedBy(AuthorizationRequest $request): AuthenticationContextRequest
    {
        if (! $this->names($request->client->tenant, $request->resources)) {
            return AuthenticationContextRequest::of($request);
        }

        return new AuthenticationContextRequest([AuthenticationContextClass::phishingResistant()->value], true);
    }

    /**
     * RFC 6749 §4.1.2.1: a request that names the administration API of its tenant, for a person who does not
     * administer it, is denied once that person is known, before any consent is asked.
     *
     * @throws AccessDeniedException when the request names that API and the person does not administer the tenant
     */
    public function assertAdministeredBy(AuthorizationRequest $request, User $user): void
    {
        if ($this->names($request->client->tenant, $request->resources) && ! $this->administrators->include($user)) {
            throw new AccessDeniedException(self::NOT_AN_ADMINISTRATOR);
        }
    }

    /**
     * RFC 8628 §5.4: a grant whose person approves the request on another device than the one of the client can be
     * started by whoever holds that client, and an administrator who approves it hands it the tokens. The device
     * authorization grant, which decision 0038 names, and the backchannel authentication grant are refused the
     * administration API when the request names it, before anybody is asked.
     *
     * @throws InvalidTargetException when the resources name the administration API of the tenant
     */
    public function assertNotNamedIn(Tenant $tenant, ?ResourceIndicators $resources): void
    {
        if ($this->names($tenant, $resources)) {
            throw InvalidTargetException::reserved();
        }
    }

    /**
     * What every access token is held to when it is minted, whatever grant mints it: one whose audience is the
     * administration API of its tenant (RFC 8707 §2, "aud") is for a person who signed in, by a session whose proofs
     * satisfy phishing_resistant, who administers the tenant now, and it is bound to a key of the client (RFC 9449
     * §6, RFC 8705 §3). A person taken out of the group is refused at the next refresh.
     *
     * @throws InvalidTargetException when the token would be addressed to that API and the authorization holds to less
     */
    public function assertMayBeAddressedBy(AuthorizationInterface $authorization): void
    {
        $administration = $this->resources->administrationResourceOf($authorization->tenant);
        if ($administration === null || ! $authorization->audience()->has($administration->value)) {
            return;
        }
        if (
            ! $authorization instanceof UserAuthorizationInterface
            || $authorization->confirmation === null
            || ! $authorization->session->satisfies(AuthenticationContextClass::phishingResistant())
            || ! $this->administrators->include($authorization->user)
        ) {
            throw InvalidTargetException::reserved();
        }
    }

    private function names(Tenant $tenant, ?ResourceIndicators $resources): bool
    {
        $administration = $this->resources->administrationResourceOf($tenant);

        return $administration !== null && $resources !== null && $resources->has($administration);
    }
}
