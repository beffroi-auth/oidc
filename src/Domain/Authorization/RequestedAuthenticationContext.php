<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use function array_filter;
use function array_values;
use Beffroi\Core\Domain\Credential\Credential;
use Beffroi\Core\Domain\Credential\ProvingCredentialInterface;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Exception\UnmetAuthenticationRequirementsException;

/**
 * OIDC Core §5.5.1.1, decision 0010
 */
final readonly class RequestedAuthenticationContext
{
    private const string UNMET_AUTHENTICATION_REQUIREMENTS = 'No requested acr value is one this provider can assert, see acr_values_supported.';

    private const string UNMET_BY_THE_USER = 'The end user holds no credential able to satisfy any requested acr value.';

    private const string UNMET_AFTER_LOGIN = 'The end user did not authenticate as any requested acr value demands.';

    /**
     * @param list<AuthenticationContextClass> $provable in the client's order of preference
     */
    private function __construct(
        public AuthenticationContextRequest $requested,
        public Tenant $tenant,
        public array $provable,
    ) {
    }

    /**
     * @param non-empty-list<AuthenticationMethod> $provableMethods
     */
    public static function of(AuthorizationRequest $request, array $provableMethods): self
    {
        return self::against(AuthenticationContextRequest::of($request), $request->client->tenant, $provableMethods);
    }

    /**
     * @param non-empty-list<AuthenticationMethod> $provableMethods
     */
    public static function against(AuthenticationContextRequest $requested, Tenant $tenant, array $provableMethods): self
    {
        return new self($requested, $tenant, $requested->among($tenant->authenticationContextPolicy->provableWith($provableMethods)));
    }

    /**
     * Whether the credentials of the user are worth reading: the request names a class the provider can prove.
     */
    public function isInQuestion(): bool
    {
        return $this->provable !== [];
    }

    /**
     * OIDC Core §5.5.1.1
     *
     * @throws UnmetAuthenticationRequirementsException only for an essential "acr"
     */
    public function assertTheProviderCanProveOne(): void
    {
        if ($this->requested->demandsAClass() && $this->provable === []) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AUTHENTICATION_REQUIREMENTS);
        }
    }

    /**
     * A credential the floor of the tenant forbids is not offered: no login here would accept it.
     *
     * @param list<Credential> $credentials
     */
    public function stepUpFor(AuthenticationSession $session, array $credentials): ?StepUp
    {
        if (! $this->isInQuestion() || $this->requested->firstSatisfiedBy($session) !== null) {
            return null;
        }

        return StepUp::towards(
            $session->proofs,
            $this->provable,
            array_values(array_filter(
                $credentials,
                fn (Credential $credential): bool => ! $credential instanceof ProvingCredentialInterface
                || $this->tenant->loginFloor->admits($credential->provableMethods()),
            )),
        );
    }

    /**
     * OIDC Core §5.5.1.1
     *
     * @throws UnmetAuthenticationRequirementsException only for an essential "acr"
     */
    public function assertTheUserCouldMeetIt(AuthenticationSession $session, ?StepUp $stepUp): void
    {
        if ($this->requested->demandsAClass() && $stepUp === null && $this->requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_BY_THE_USER);
        }
    }

    /**
     * OIDC Core §5.5.1.1
     *
     * @throws UnmetAuthenticationRequirementsException only for an essential "acr"
     */
    public function assertMetBy(AuthenticationSession $session): void
    {
        if ($this->requested->demandsAClass() && $this->requested->firstSatisfiedBy($session) === null) {
            throw new UnmetAuthenticationRequirementsException(self::UNMET_AFTER_LOGIN);
        }
    }

    public function classFor(AuthenticationSession $session): AuthenticationContextClass
    {
        return $this->requested->firstSatisfiedBy($session) ?? $session->authenticationContextClass();
    }
}
