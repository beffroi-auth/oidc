<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Trust;

use function count;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Domain\Trust\VerifiedAssertion;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidGrantException;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use Beffroi\Oidc\Port\TrustedIssuersInterface;
use function in_array;
use SensitiveParameter;

/**
 * What an assertion presented as an authorization has to say (RFC 7523 §3): signed by an issuer the tenant
 * trusts, with a key that issuer published, addressed to this provider, still valid, and not seen before.
 *
 * Every refusal is the same refusal. Whoever presents an assertion learns that it was not accepted and nothing
 * else: not whether the issuer is known, not whether the client may present its assertions, not whether the
 * subject resolves. A grant that mints a user is a grant whose error responses teach nothing about what the
 * tenant trusts.
 *
 * It shares nothing with the reading of the assertion that authenticates a client (ClientAssertionValidator,
 * RFC 7523 §2.2): different registrations, different keys, different rules and a replay guard of its own, so
 * that an assertion accepted here is not thereby accepted there, nor the other way round (§2.1).
 */
final readonly class IssuerAssertionValidator
{
    /**
     * The one thing a client is told, whatever went wrong.
     */
    private const string REFUSED = 'The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    /**
     * @param DateInterval $maximumLifetime how far ahead of the request an "exp" may be
     * @param DateInterval $leeway what is allowed of the clock of the issuer, both ways
     */
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private JwtKeyVerifierInterface $keys,
        private TrustedIssuersInterface $issuers,
        private IssuerAssertionReplayGuardInterface $replays,
        private DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @param string $assertion the compact JWS the request presented
     *
     * @throws InvalidGrantException whenever the assertion is not accepted, whatever the reason
     */
    public function validate(Tenant $tenant, Client $client, #[SensitiveParameter] string $assertion, DateTimeImmutable $now): VerifiedAssertion
    {
        try {
            $jwt = $this->jwts->read($assertion);
        } catch (InvalidJwtException $exception) {
            throw new InvalidGrantException(self::REFUSED, previous: $exception);
        }
        $issuer = $this->trusting($tenant, $client, $jwt);
        try {
            // RFC 8725 §3.10: the key is one the tenant registered for this issuer, chosen by the "kid" of
            // the header among those and by nothing the assertion carries otherwise
            $this->keys->verify($jwt, $issuer->keys, $issuer->signingAlgorithms);
        } catch (InvalidJwtException $exception) {
            throw new InvalidGrantException(self::REFUSED, previous: $exception);
        }
        $this->assertItIsStillGood($tenant, $issuer, $jwt, $now);

        try {
            return new VerifiedAssertion($issuer, $jwt->claim('sub') ?? '');
        } catch (InvalidArgumentException $exception) {
            throw new InvalidGrantException(self::REFUSED, previous: $exception);
        }
    }

    /**
     * RFC 7523 §3: the issuer the assertion names, among the ones this tenant trusts, and among the ones this
     * client may present the assertions of. Nothing of the assertion is verified before this: which key would
     * verify it is the registration's answer and never the assertion's.
     *
     * @throws InvalidGrantException
     */
    private function trusting(Tenant $tenant, Client $client, UnverifiedJwt $jwt): TrustedIssuer
    {
        $named = $jwt->claim('iss');
        $issuer = $named === null ? null : $this->issuers->find($tenant, $named);
        if ($issuer === null || ! $issuer->allowsClient($client->registration->clientId)) {
            throw new InvalidGrantException(self::REFUSED);
        }

        return $issuer;
    }

    /**
     * RFC 7523 §3: addressed to this provider, once and by its issuer identifier; expired or not yet issued,
     * refused; and bounded, so that an assertion is not a bearer token for a year. FAPI 2.0 Security Profile
     * §5.3.2.1 clause 8 makes the issuer identifier the one name accepted, which is the rule this provider
     * holds every assertion to (#267).
     *
     * @throws InvalidGrantException
     */
    private function assertItIsStillGood(Tenant $tenant, TrustedIssuer $issuer, UnverifiedJwt $jwt, DateTimeImmutable $now): void
    {
        $audiences = $jwt->audiences();
        if (count($audiences) !== 1 || ! in_array($tenant->issuer->value, $audiences, true)) {
            throw new InvalidGrantException(self::REFUSED);
        }
        $expiresAt = $jwt->time('exp');
        if ($expiresAt === null || $expiresAt <= $now->sub($this->leeway) || $expiresAt > $now->add($this->leeway)->add($this->maximumLifetime)) {
            throw new InvalidGrantException(self::REFUSED);
        }
        $issuedAt = $jwt->time('iat');
        if ($issuedAt === null || $issuedAt > $now->add($this->leeway)) {
            throw new InvalidGrantException(self::REFUSED);
        }
        $jti = $jwt->claim('jti');
        if ($jti === null || ! $this->replays->remember($tenant, $issuer, $jti, $expiresAt)) {
            throw new InvalidGrantException(self::REFUSED);
        }
    }
}
