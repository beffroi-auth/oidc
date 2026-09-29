<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function count;
use DateInterval;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;
use Heidi\Oidc\Exception\InvalidSoftwareStatementException;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use Heidi\Oidc\Port\JwtKeyVerifierInterface;
use Heidi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use function in_array;
use SensitiveParameter;

/**
 * What a software statement has to say before any of it is read as metadata (RFC 7591 §2.3): signed by an
 * authority the policy of the tenant pinned, with a key that policy holds, addressed to this provider,
 * still valid, and not seen before.
 *
 * Nothing of the statement is verified before the authority is found: which key would verify it is the
 * policy's answer and never the statement's (RFC 8725 §3.10). A statement carrying its own key, or naming
 * a "jwks_uri" of its own, is verified against neither, which is what keeps whoever can sign anything from
 * signing themselves an attestation.
 *
 * Every refusal is the same refusal, `invalid_software_statement`, and whoever presents a statement learns
 * that it was not accepted and nothing else: not whether the authority is pinned, not whether the
 * signature verified, not whether the identifier had been seen (decision 0006).
 *
 * It shares nothing with the two readings of an assertion (RFC 7523 §2.1, §3): different registrations,
 * different keys, different rules and a replay guard of its own.
 */
final readonly class SoftwareStatementVerifier
{
    /**
     * @param DateInterval $maximumLifetime how far ahead of the request an "exp" may be
     * @param DateInterval $leeway what is allowed of the clock of the authority, both ways
     */
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private JwtKeyVerifierInterface $keys,
        private SoftwareStatementReplayGuardInterface $replays,
        private DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @param string $statement the compact JWS the registration carried
     *
     * @throws InvalidSoftwareStatementException whenever the statement is not accepted, whatever the reason
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
     * RFC 7591 §2.3: the authority the statement names, among the ones the policy of this tenant pinned.
     *
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
     * Addressed to this provider, once and by its issuer identifier; expired or not yet issued, refused;
     * bounded, so that a statement is not a registration credential for a year; and remembered, so that one
     * statement registers one client.
     *
     * RFC 7591 §2.3 requires none of these of a statement, the "software_statement" being defined as a JWT
     * whose claims are metadata and nothing more. They are required here for the same reason every other
     * signed thing this provider takes back is held to them (decision 0006): a statement with no "exp" is a
     * bearer credential for ever, and one no audience names is one an authority signed for somebody else.
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
