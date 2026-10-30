<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use function array_any;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\DeclaredScopesInterface;
use function sprintf;

/**
 * The scopes a deployment declares for the tenant it declares (architecture §5.1, issue #920), read once, when this
 * service is built: a value that is no scope token, or a scope that being declared does not make offered, refuses that
 * construction, whether the deployment wrote the list or the environment carried it. They belong to the tenant this
 * deployment declares, which is why the list is told its slug: asked about another tenant, this answers as a tenant
 * that declares none.
 */
final readonly class ConfigurationDeclaredScopes implements DeclaredScopesInterface
{
    /**
     * @var list<Scope>
     */
    private array $scopes;

    /**
     * @param list<string> $scopes the scope tokens the deployment declares (RFC 6749 §3.3), a token repeated counting once; none for a deployment that declares none
     *
     * @throws InvalidArgumentException when one is no scope token, or is "offline_access", which the wired grants decide (OIDC Core §11)
     */
    public function __construct(
        private string $tenantSlug,
        array $scopes = [],
    ) {
        $declared = [];
        foreach ($scopes as $value) {
            $scope = $this->scope($value);
            if (! array_any($declared, static fn (Scope $kept): bool => $kept->equals($scope))) {
                $declared[] = $scope;
            }
        }
        $this->scopes = $declared;
    }

    public function scopesDeclaredFor(Tenant $tenant): array
    {
        return $tenant->slug === $this->tenantSlug ? $this->scopes : [];
    }

    /**
     * @throws InvalidArgumentException when the value is no scope token, or is "offline_access"
     */
    private function scope(string $value): Scope
    {
        try {
            $scope = new Scope($value);
        } catch (InvalidArgumentException $refusal) {
            throw new InvalidArgumentException(
                sprintf('The scope "%s" is declared for the tenant "%s", and it is not a scope token (RFC 6749 §3.3).', $value, $this->tenantSlug),
                0,
                $refusal,
            );
        }
        if ($scope->equals(Scope::offlineAccess())) {
            throw new InvalidArgumentException(sprintf(
                'The scope "offline_access" is declared for the tenant "%s": it asks for a refresh token (OIDC Core §11), which the tenant offers where the wired grants issue and spend one, and never because it is declared.',
                $this->tenantSlug,
            ));
        }

        return $scope;
    }
}
