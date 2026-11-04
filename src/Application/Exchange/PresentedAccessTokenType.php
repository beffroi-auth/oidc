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
 * RFC 8693 §3
 *
 * Read through AccessTokenInspector, so a token of a session somebody ended cannot be exchanged for a fresh one.
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
            $verified->scopes ?? throw new InvalidRequestException('The presented token says nothing of what it is good for.'),
            $verified->audience,
            $verified->grantId,
            $verified->signIn,
            $verified->actor,
            $verified->client->registration->mayAct,
            $inspected->user?->subject,
        );
    }
}
