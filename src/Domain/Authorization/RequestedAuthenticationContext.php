<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Exception\UnmetAuthenticationRequirementsException;

/**
 * What a request demands of the authentication, judged against what this provider can prove (decision
 * 0010): the "acr" the request asks for, and the requested classes the policy of the tenant can assert with
 * the methods the provider is wired to prove. The rules of OIDC Core §5.5.1.1 are here and nowhere else,
 * asked at the three moments they answer differently.
 *
 * It holds no port, reads no store and tells no time: the three refusals and the step-up are functions of
 * the request, of the policy, of the session and of the credentials the user holds, and nothing more. What
 * reads a session's credentials, and when, is the caller's (AuthenticationRequirement), because reading them
 * costs a query and only a request that binds the provider to a class needs them.
 *
 * An essential "acr" is the only one that refuses: a voluntary one is never refused and is answered with the
 * class the session has (§5.5.1.1).
 */
final readonly class RequestedAuthenticationContext
{
    private const string UNMET_AUTHENTICATION_REQUIREMENTS = 'No requested acr value is one this provider can assert, see acr_values_supported.';

    private const string UNMET_BY_THE_USER = 'The end user holds no credential able to satisfy any requested acr value.';

    private const string UNMET_AFTER_LOGIN = 'The end user did not authenticate as any requested acr value demands.';

    /**
     * @param list<AuthenticationContextClass> $provable the requested classes the provider can prove, in the client's order of preference
     */
    private function __construct(
        public AuthenticationContextRequest $requested,
        public array $provable,
    ) {
    }

    /**
     * What an authorization request asks of the authentication (OIDC Core §3.1.2.1, §5.5.1.1).
     *
     * @param non-empty-list<AuthenticationMethod> $provableMethods what the provider is wired to prove
     */
    public static function of(AuthorizationRequest $request, array $provableMethods): self
    {
        return self::against(AuthenticationContextRequest::of($request), $request->client->tenant, $provableMethods);
    }

    /**
     * The same rules for a request that is not an authorization request: what is asked of the user of a
     * backchannel authentication request is asked of the same policy, judged against the same wiring and
     * answered on the same page of the provider (CIBA Core §7.1, decision 0010). The demand is read where
     * that request was read, and what it means is decided once, here.
     *
     * @param non-empty-list<AuthenticationMethod> $provableMethods what the provider is wired to prove
     */
    public static function against(AuthenticationContextRequest $requested, Tenant $tenant, array $provableMethods): self
    {
        return new self($requested, $requested->among($tenant->authenticationContextPolicy->provableWith($provableMethods)));
    }

    /**
     * Whether a class is in question at all, which is what makes the credentials of the user worth reading:
     * a request that names none, and one whose classes the provider cannot prove, are answered without them.
     */
    public function isInQuestion(): bool
    {
        return $this->provable !== [];
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" naming only classes the provider cannot assert fails without a
     * login; a voluntary one is never refused.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    public function assertTheProviderCanProveOne(): void
    {
        if ($this->requested->demandsAClass() && $this->provable === []) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AUTHENTICATION_REQUIREMENTS);
        }
    }

    /**
     * Decision 0010: the client asked for classes the provider can prove, the session satisfies none and a
     * credential of the user would, so the login page asks for what is missing rather than for a new login.
     *
     * @param list<Credential> $credentials the credentials of the user of the session, whatever their kind
     */
    public function stepUpFor(AuthenticationSession $session, array $credentials): ?StepUp
    {
        if (! $this->isInQuestion() || $this->requested->firstSatisfiedBy($session) !== null) {
            return null;
        }

        return StepUp::towards($session->proofs, $this->provable, $credentials);
    }

    /**
     * OIDC Core §5.5.1.1, as for a class the provider cannot prove: an essential "acr" the session does not
     * satisfy and no credential of the user could is a failed authentication before any page, the user can do
     * nothing about it there; a voluntary one gets the class the session has.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    public function assertTheUserCouldMeetIt(AuthenticationSession $session, ?StepUp $stepUp): void
    {
        if ($this->requested->demandsAClass() && $stepUp === null && $this->requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_BY_THE_USER);
        }
    }

    /**
     * OIDC Core §5.5.1.1: an essential "acr" still unsatisfied once the login of this interaction is done is
     * a failed authentication; a voluntary one gets the class the session has.
     *
     * @throws UnmetAuthenticationRequirementsException
     */
    public function assertMetBy(AuthenticationSession $session): void
    {
        if ($this->requested->demandsAClass() && $this->requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AFTER_LOGIN);
        }
    }

    /**
     * The class every token descending from this grant will name (OIDC Core §2): the requested one the session
     * satisfies, and the one the session has when the request asked for none in particular.
     */
    public function classFor(AuthenticationSession $session): AuthenticationContextClass
    {
        return $this->requested->firstSatisfiedBy($session) ?? $session->authenticationContextClass();
    }
}
