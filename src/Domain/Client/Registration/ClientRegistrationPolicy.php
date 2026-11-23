<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Registration;

use function array_find;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;

final readonly class ClientRegistrationPolicy
{
    /**
     * The default of refresh_token_absolute_ttl: past it, nothing the client was issued can be presented.
     */
    public const string UNUSED_FOR = 'P90D';

    public const string NEVER_USED_FOR = 'P7D';

    /**
     * @param list<StatementIssuer> $statementIssuers
     *
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $mode,
        public bool $exemptsConfidentialClientsFromPkce = false,
        public DateInterval $keepsAClientUnusedFor = new DateInterval(self::UNUSED_FOR),
        public DateInterval $keepsAClientNeverUsedFor = new DateInterval(self::NEVER_USED_FOR),
        public array $statementIssuers = [],
        public ?Scopes $defaultScopes = null,
    ) {
        if ($mode === '') {
            throw new InvalidArgumentException('A registration policy names what authorises a registration (decision 0009); a tenant that authorises none has no policy at all.');
        }
    }

    public function trusts(string $issuer): ?StatementIssuer
    {
        return array_find($this->statementIssuers, static fn (StatementIssuer $pinned): bool => $pinned->issuer === $issuer);
    }

    public function retentionAt(DateTimeImmutable $now): ClientRetention
    {
        return ClientRetention::at($now, $this->keepsAClientUnusedFor, $this->keepsAClientNeverUsedFor);
    }

    /**
     * A public client is never exempted from PKCE, which alone binds its code to it (RFC 9700 §2.1.1).
     * A member the client named is never written: what is written outranks what the client sent.
     *
     * @return array<string, mixed>
     */
    public function membersWrittenOn(ClientAuthenticationMethodInterface $method, ClientMetadata $registered): array
    {
        $written = [];
        if ($this->defaultScopes !== null && ! $registered->has('scope')) {
            $written['scope'] = (string) $this->defaultScopes;
        }
        if ($this->exemptsConfidentialClientsFromPkce && $method->authenticatesClient()) {
            $written['requires_pkce'] = false;
        }

        return $written;
    }
}
