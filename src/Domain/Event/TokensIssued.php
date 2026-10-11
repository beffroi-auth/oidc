<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The token endpoint answered a client: what was authorized and which tokens left, never their values.
 *
 * It names the person the tokens were issued in the name of by the subject their account carries and never
 * by the "sub" the client was answered (issue #588): a pairwise subject (OIDC Core §8.1) is the name one
 * client sees, so an act written under one is an act the journal of that person does not find.
 *
 * **It carries what the client was given**, which the journal cannot keep (issue #590): the scopes it may
 * now obtain, what it had asked for by name, what it was given beyond the scopes and the shape its access
 * token was written in. A row beside the act holds them, written out of this event and never out of a
 * second reading of the grant.
 */
final readonly class TokensIssued implements ClientInUseInterface, ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'tokens.issued';

    /**
     * @param ConfirmationInterface|null $confirmation what the tokens that left are bound to, null for bearer ones (RFC 9449 §6, RFC 8705 §3)
     * @param Subject|null $subject the person the tokens were issued in the name of, by the subject their account carries; null when they were issued in nobody's (RFC 6749 §4.4)
     * @param ClaimsRequest|null $claimsRequest what the client had asked for by name (OIDC Core §5.5), null when it asked for none and for a grant nobody was asked for
     * @param AuthorizationDetails|null $authorizationDetails what the response carries beyond its scopes (RFC 9396 §7), null when it carries none
     * @param string $tokenShape the shape the access token was written in (architecture §4.6), as the shape names itself
     * @param Uuid|null $sessionId the session the tokens descend from, null when nobody signed in for them (RFC 6749 §4.4)
     * @param string|null $refreshTokenHash the refresh token that left, by its hash, null when none did
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public GrantTypeName $grantType,
        public Uuid $grantId,
        public string $clientId,
        public ?Subject $subject,
        public ?Uuid $sessionId,
        public Scopes $grantedScopes,
        public DateTimeImmutable $accessTokenExpiresAt,
        public bool $idTokenIssued,
        public ?ConfirmationInterface $confirmation,
        public ?string $refreshTokenHash,
        public ?ClaimsRequest $claimsRequest,
        public ?AuthorizationDetails $authorizationDetails,
        public string $tokenShape,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): ?Subject
    {
        return $this->subject;
    }
}
