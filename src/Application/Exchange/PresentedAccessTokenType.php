<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Exchange;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Token\AccessTokenInspector;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidTokenException;
use SensitiveParameter;

/**
 * RFC 8693 §3 "urn:ietf:params:oauth:token-type:access_token": an access token of this provider, of either
 * shape, presented as the subject of an exchange or as the actor of one.
 *
 * It is read the way every resource of this provider reads one (AccessTokenInspector): verified, descending
 * from a session that has not ended and from a grant still alive, naming a user still served. A token the
 * provider would refuse at its UserInfo endpoint is a token it refuses to exchange, so a session somebody
 * ended cannot be turned into a fresh token by a service that kept the old one.
 *
 * What the exchange is told is that the token is not good, and nothing more (RFC 8693 §2.2.2): which of the
 * questions it failed is the provider's business and not the caller's.
 */
final readonly class PresentedAccessTokenType implements PresentedTokenTypeInterface
{
    public function __construct(
        private AccessTokenInspector $tokens,
    ) {
    }

    public function identifier(): TokenTypeIdentifier
    {
        return TokenTypeIdentifier::accessToken();
    }

    public function read(Tenant $tenant, #[SensitiveParameter] string $token, DateTimeImmutable $now): PresentedToken
    {
        try {
            $inspected = $this->tokens->inspect($tenant, $token, $now);
        } catch (InvalidTokenException $exception) {
            throw new InvalidRequestException('The presented token is not one this provider honours (RFC 8693 section 2.2.2).', previous: $exception);
        }
        $verified = $inspected->token;

        return new PresentedToken(
            $verified->subject,
            $verified->client,
            // RFC 9068 §2.2.3: a token this provider issued always says what it is good for
            $verified->scopes ?? throw new InvalidRequestException('The presented token says nothing of what it is good for.'),
            $verified->audience,
            $verified->grantId,
            $verified->signIn,
            $verified->actor,
            // RFC 8693 §4.4: who may act for the subject of a token of this client, as its registration
            // says it; one place decides, and the claim the self-contained shape carries is written from it
            $verified->client->registration->mayAct,
            // the user the inspection read the "sub" back as, so that what the exchange issues is written
            // in the journal of that person and not under a name only the first client holds (issue #588)
            $inspected->user?->subject,
        );
    }
}
