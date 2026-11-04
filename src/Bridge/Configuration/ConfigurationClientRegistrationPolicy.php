<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use DateInterval;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\ClientRegistrationPolicyInterface;

/**
 * Decision 0009
 *
 * An empty value is no value: it is what an environment variable declared empty gives.
 */
final readonly class ConfigurationClientRegistrationPolicy implements ClientRegistrationPolicyInterface
{
    /**
     * @var list<StatementIssuer>
     */
    private array $pinned;

    private ?Scopes $defaultScopes;

    /**
     * @param string|null $mode null or empty for a deployment that registers nobody
     * @param DateInterval|null $keepsAClientUnusedFor null for the default of the policy
     * @param DateInterval|null $keepsAClientNeverUsedFor null for the default of the policy
     * @param array<string, array<string, mixed>> $statementIssuers keyed by the "iss" they sign with
     * @param string|null $defaultScope space-delimited; null or empty for a deployment that writes none
     *
     * @throws InvalidArgumentException
     * @throws LogicException when authorities are declared and nothing is wired to verify what they sign with
     */
    public function __construct(
        private string $tenantSlug,
        private ?string $mode = null,
        private bool $exemptsConfidentialClientsFromPkce = false,
        private ?DateInterval $keepsAClientUnusedFor = null,
        private ?DateInterval $keepsAClientNeverUsedFor = null,
        array $statementIssuers = [],
        ?SignatureAlgorithmsInterface $algorithms = null,
        ?string $defaultScope = null,
    ) {
        $pinned = [];
        if ($statementIssuers !== []) {
            if ($algorithms === null) {
                throw new LogicException('The registration policy pins the issuer of a software statement, and nothing is wired to verify what it signs with (RFC 7591 section 2.3).');
            }
            foreach ($statementIssuers as $issuer => $definition) {
                $pinned[] = StatementIssuerDefinition::fromArray((string) $issuer, $definition, $algorithms)->issuer;
            }
        }
        $this->pinned = $pinned;
        $this->defaultScopes = $defaultScope === null || $defaultScope === '' ? null : Scopes::parse($defaultScope);
    }

    public function policyFor(Tenant $tenant): ?ClientRegistrationPolicy
    {
        if ($tenant->slug !== $this->tenantSlug || $this->mode === null || $this->mode === '') {
            return null;
        }

        return new ClientRegistrationPolicy(
            $this->mode,
            $this->exemptsConfidentialClientsFromPkce,
            $this->keepsAClientUnusedFor ?? new DateInterval(ClientRegistrationPolicy::UNUSED_FOR),
            $this->keepsAClientNeverUsedFor ?? new DateInterval(ClientRegistrationPolicy::NEVER_USED_FOR),
            $this->pinned,
            $this->defaultScopes,
        );
    }
}
