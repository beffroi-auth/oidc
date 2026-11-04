<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function count;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Exception\InvalidSoftwareStatementException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use Beffroi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use function in_array;
use SensitiveParameter;

/**
 * RFC 7591 §2.3, RFC 8725 §3.10
 *
 * Verified only against the keys the tenant's policy pinned, never a key or "jwks_uri" the statement names.
 */
final readonly class SoftwareStatementVerifier
{
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private JwtKeyVerifierInterface $keys,
        private SoftwareStatementReplayGuardInterface $replays,
        private DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @throws InvalidSoftwareStatementException whatever the reason the statement is refused
     * @throws InvalidClientMetadataException when the statement carries a member of this provider alone
     */
    public function verify(
        Tenant $tenant,
        ClientRegistrationPolicy $policy,
        #[SensitiveParameter]
        string $statement,
        DateTimeImmutable $now,
    ): AttestedMembers {
        try {
            $jwt = $this->jwts->read($statement);
        } catch (InvalidJwtException $exception) {
            throw new InvalidSoftwareStatementException(previous: $exception);
        }
        $issuer = $this->pinned($policy, $jwt);
        try {
            $this->keys->verify($jwt, $issuer->keys, $issuer->signingAlgorithms);
        } catch (InvalidJwtException $exception) {
            throw new InvalidSoftwareStatementException(previous: $exception);
        }
        $this->assertItIsStillGood($tenant, $issuer, $jwt, $now);

        return new AttestedMembers($jwt->claims);
    }

    /**
     * @throws InvalidSoftwareStatementException
     */
    private function pinned(ClientRegistrationPolicy $policy, UnverifiedJwt $jwt): StatementIssuer
    {
        $named = $jwt->claim('iss');
        $issuer = $named === null ? null : $policy->trusts($named);
        if ($issuer === null) {
            throw new InvalidSoftwareStatementException();
        }

        return $issuer;
    }

    /**
     * Beyond what RFC 7591 §2.3 asks: without these checks a statement would be a bearer credential for ever.
     *
     * @throws InvalidSoftwareStatementException
     */
    private function assertItIsStillGood(Tenant $tenant, StatementIssuer $issuer, UnverifiedJwt $jwt, DateTimeImmutable $now): void
    {
        $audiences = $jwt->audiences();
        if (count($audiences) !== 1 || ! in_array($tenant->issuer->value, $audiences, true)) {
            throw new InvalidSoftwareStatementException();
        }
        $expiresAt = $jwt->time('exp');
        if ($expiresAt === null || $expiresAt <= $now->sub($this->leeway) || $expiresAt > $now->add($this->leeway)->add($this->maximumLifetime)) {
            throw new InvalidSoftwareStatementException();
        }
        $issuedAt = $jwt->time('iat');
        if ($issuedAt === null || $issuedAt > $now->add($this->leeway)) {
            throw new InvalidSoftwareStatementException();
        }
        $jti = $jwt->claim('jti');
        if ($jti === null || ! $this->replays->remember($tenant, $issuer, $jti, $expiresAt)) {
            throw new InvalidSoftwareStatementException();
        }
    }
}
