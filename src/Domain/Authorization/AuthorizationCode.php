<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Heidi\Oidc\Domain\Grant\GrantRecord;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\KeyConfirmation;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * An authorization code (RFC 6749 §4.1.2, architecture §4.4) as the provider keeps it: the SHA-256 of the
 * value, and everything the token endpoint needs, what the session had proven, frozen in an
 * AuthenticationSnapshot at issuance. The record is also the grant the tokens descend from
 * (GrantRecord), revoked when the code is replayed (RFC 6749 §4.1.2).
 */
final class AuthorizationCode extends GrantRecord implements ResolvesItsClientInterface
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * @param string $codeHash the hex SHA-256 of the value drawn for it, see DrawnSecret
     * @param CodeChallenge|null $codeChallenge null only for a client that does not require PKCE (decision 0008)
     * @param ResourceIndicators|null $resources the resources the request asked the tokens for (RFC 8707 §2.1), null when it named none; a token request may narrow them and never widen them
     * @param AuthorizationDetails|null $authorizationDetails what the user agreed to beyond the scopes (RFC 9396 §2), null when the request asked for none; a token request may narrow them and never widen them
     * @param KeyConfirmation|null $dpopKey the key the request reserved the code for (RFC 9449 §10), null when it reserved it for none
     * @param AuthenticationSnapshot $authentication what the session had proven, frozen for every token of the grant
     */
    public function __construct(
        public readonly string $codeHash,
        public readonly Uuid $grantId,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        public readonly RedirectUri $redirectUri,
        public readonly Scopes $scopes,
        public readonly ?ResourceIndicators $resources,
        public readonly ?AuthorizationDetails $authorizationDetails,
        public readonly ?string $nonce,
        public readonly ?CodeChallenge $codeChallenge,
        public readonly ?KeyConfirmation $dpopKey,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly AuthenticationSnapshot $authentication,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (! DrawnSecret::isDigest($codeHash)) {
            throw new InvalidArgumentException('An authorization code is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization code binds a session and a client of the same tenant.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An authorization code expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    protected function nameOfRecord(): string
    {
        return 'An authorization code';
    }

    protected function readerThatChecks(): string
    {
        return 'the grant';
    }

    public function clientHolder(): object
    {
        return $this;
    }
}
