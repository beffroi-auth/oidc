<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Symfony\Component\Uid\Uuid;

/**
 * What a verified grant entitles the client to (architecture §4.5), read by the token issuers: the client,
 * the scopes of the response and the ones it was granted, the resources it is addressed to, and what the
 * tokens of the response are bound to.
 *
 * This is what every authorization carries, whoever is behind it. What only an authorization somebody
 * signed in for carries, the session, the user and what that session had proven, is declared by
 * UserAuthorizationInterface, and an issuer that needs it asks for it there: the tokens of a service
 * (RFC 6749 §4.4) are not the tokens of a user with the claims about the user left out.
 *
 * "scopes" is what this response carries, "grantedScopes" what the authorization stands on (RFC 6749 §6);
 * "resources" and "grantedResources" say the same of the resources the access token is addressed to
 * (RFC 8707 §2.2), a token request being free to narrow either and to widen neither.
 */
interface AuthorizationInterface
{
    /**
     * The grant that produced this authorization, as it names itself.
     */
    public GrantTypeName $grantType { get; }

    public Uuid $grantId { get; }

    public Client $client { get; }

    public Tenant $tenant { get; }

    public Scopes $scopes { get; }

    public Scopes $grantedScopes { get; }

    /**
     * The resources this response is for ("resource", RFC 8707 §2), null when the request named none.
     */
    public ?ResourceIndicators $resources { get; }

    /**
     * The resources the authorization carries, null when it carries none.
     */
    public ?ResourceIndicators $grantedResources { get; }

    /**
     * What the tokens of this response are bound to (RFC 8705 §3, RFC 9449 §6.1), null when they are
     * bearer tokens.
     */
    public ?ConfirmationInterface $confirmation { get; }

    /**
     * Who the access token of this response is addressed to (RFC 8707 §2), written by both shapes of
     * access token and rendered by the introspection of the opaque one.
     */
    public function audience(): TokenAudience;

    /**
     * The record the access token of this response is kept as when its shape is the opaque one
     * (architecture §4.6), under the digest of the value drawn for it. Each kind of authorization writes
     * the record of its own kind, so nothing that keeps one has to recognise which kind it was handed.
     */
    public function storedUnder(string $tokenHash, DateTimeImmutable $now, DateTimeImmutable $expiresAt): StoredAccessToken;
}
