<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use DateTimeImmutable;
use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * A client gave a token back at the revocation endpoint (RFC 7009 §2.1). Which kind it gave back is
 * named by whoever revoked it, in the words of the "token_type_hint" of §2.1: the caller knows what it
 * revoked, so nothing here reads a class name to find out.
 *
 * It names the person the token was issued in the name of, which the record of that token answers for
 * (issue #588). Two records name nobody: one a client held for itself (RFC 6749 §4.4), and one whose
 * subject was named by what a client presented, the "sub" it keeps being a name only that client holds
 * (RFC 8693 §2.2.1, issue #593).
 */
final readonly class TokenRevoked implements ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'token.revoked';

    public const string REFRESH_TOKEN = 'refresh_token';

    public const string ACCESS_TOKEN = 'access_token';

    /**
     * @param Subject|null $subject the person the token was issued in the name of, null when the record names nobody
     * @param string $tokenType "refresh_token" or "access_token" (RFC 7009 §2.1)
     * @param list<string> $revokedAccessTokenHashes the access tokens revoked along with a refresh token (§2.1)
     */
    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public string $revokedBy,
        public ?Subject $subject,
        public string $tokenType,
        public string $tokenHash,
        public Uuid $grantId,
        public array $revokedAccessTokenHashes,
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
