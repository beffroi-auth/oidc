<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Trust;

use function count;
use DateInterval;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Key\PublishedKeySetProvider;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Domain\Trust\TrustedIssuer;
use Beffroi\Oidc\Domain\Trust\VerifiedAssertion;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
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
 * RFC 7523 §3
 */
final readonly class IssuerAssertionValidator
{
    /**
     * The one refusal, whatever went wrong, so that an error teaches nothing about what the tenant trusts.
     */
    private const string REFUSED = 'The assertion is not one this provider accepts as an authorization (RFC 7523 section 3).';

    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private JwtKeyVerifierInterface $keys,
        private PublishedKeySetProvider $publishedKeys,
        private TrustedIssuersInterface $issuers,
        private IssuerAssertionReplayGuardInterface $replays,
        private DateInterval $maximumLifetime,
        private DateInterval $leeway,
    ) {
    }

    /**
     * Remembers nothing: spend() records the "jti" that refuses a replay.
     *
     * @throws InvalidGrantException
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
            // An issuer whose keys cannot be read gets the same refusal, so that a client learns nothing of whom
            // the tenant trusts.
            $this->keys->verify($jwt, $this->publishedKeys->keysOf($issuer->keys, $jwt->keyId()), $issuer->signingAlgorithms);
        } catch (ClientKeysUnavailableException|InvalidJwtException $exception) {
            throw new InvalidGrantException(self::REFUSED, previous: $exception);
        }

        return $this->verified($tenant, $issuer, $jwt, $now);
    }

    /**
     * RFC 7523 §3
     *
     * Called last, once the response has read what it needs from outside the provider, so that an outage leaves
     * the assertion unspent.
     *
     * @throws InvalidGrantException
     */
    public function spend(Tenant $tenant, VerifiedAssertion $verified): void
    {
        if (! $this->replays->remember($tenant, $verified->issuer, $verified->jti, $verified->expiresAt->add($this->leeway))) {
            throw new InvalidGrantException(self::REFUSED);
        }
    }

    /**
     * RFC 7523 §3
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
     * RFC 7523 §3, FAPI 2.0 Security Profile §5.3.2.1 clause 8
     *
     * @throws InvalidGrantException
     */
    private function verified(Tenant $tenant, TrustedIssuer $issuer, UnverifiedJwt $jwt, DateTimeImmutable $now): VerifiedAssertion
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
        if ($jti === null) {
            throw new InvalidGrantException(self::REFUSED);
        }

        try {
            return new VerifiedAssertion($issuer, $jwt->claim('sub') ?? '', $jti, $expiresAt);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidGrantException(self::REFUSED, previous: $exception);
        }
    }
}
