<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Ciba;

use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Heidi\Oidc\Domain\Grant\GrantRecord;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Symfony\Component\Uid\Uuid;
use function max;

/**
 * What the provider keeps of a backchannel authentication request (CIBA Core §7): the SHA-256 of the
 * identifier the client polls with, the client it is bound to, what the request asked for, the user it
 * named, and the message that user will be shown where they approve. Where the client asked from is kept
 * beside them, because the page that asks for the approval says so (BCP 10027 §5.2): a request nobody
 * started must look like one nobody started.
 *
 * It is a record and not a request: it outlives the request that created it, with a lifetime, a use and a
 * state of its own, exactly as the device authorization request is. Two things happen to it. The user
 * answers it, once, yes or no; and the client spends it, once, the record being read once as an
 * authorization code is (RecordReadOnce). An answered record that nobody spent stays until it expires,
 * and a spent one stays so that the next presentation is told from an identifier nobody ever issued.
 *
 * A request whose hint named nobody is a record with no user, which nobody can ever answer and which
 * expires as every unanswered one does. That is deliberate and it is the whole of this provider's answer
 * to §13 "unknown_user_id": what the login page is built not to say (decision 0006, architecture §3.4) is
 * not said here either, and a client that names a stranger learns exactly what a client that names
 * somebody who never answers learns.
 *
 * What the client would like that user to prove is kept with the rest of what it asked for, and it is a
 * demand on the approval and not on the request: whether the session somebody holds proves a class is a
 * question about that person, and asking it at the endpoint would answer, to whoever authenticated as a
 * client, something about a user they only named (§13 "unknown_user_id" above).
 *
 * The session the user answered with, and what that session had proven then, are frozen here: the tokens
 * the client comes for descend from the approval and not from whatever the session became afterwards
 * (architecture §4.6). The record is also the grant those tokens descend from (GrantRecord): this flow
 * writes no authorization code, and a resource of this provider asks of a token whether the grant behind
 * it is still alive.
 */
final class BackchannelAuthenticationRecord extends GrantRecord implements ResolvesItsClientInterface
{
    /**
     * CIBA Core §7.3: the seconds a client waits between two polls when the response names none.
     */
    public const int DEFAULT_INTERVAL = 5;

    /**
     * CIBA Core §11: what "slow_down" adds to the interval, for that request and every one after it.
     */
    public const int INTERVAL_INCREASE = 5;

    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * CIBA Core §11: the seconds the client is asked to wait between two polls, as this record has come
     * to expect them.
     *
     * @var positive-int
     */
    public private(set) int $interval;

    public private(set) ?DateTimeImmutable $lastPolledAt = null;

    public private(set) ?DateTimeImmutable $approvedAt = null;

    public private(set) ?DateTimeImmutable $deniedAt = null;

    public private(set) ?AuthenticationSession $session = null;

    public private(set) ?AuthenticationSnapshot $authentication = null;

    /**
     * @param string $authRequestIdHash the hex SHA-256 of the auth_req_id (DrawnSecret)
     * @param Uuid $grantId the grant the tokens of this request will name
     * @param User|null $user the user the hint named, null when it named nobody
     * @param Scopes $scopes what the request asked for, among the ones the client registered
     * @param ResourceIndicators|null $resources what the access token will be addressed to (RFC 8707 §2), null when the request named none
     * @param BindingMessage|null $bindingMessage what the user is shown beside the name of the client (§7.1)
     * @param list<string> $acrValues the classes the client would like the authentication to reach, in its order of preference (§7.1)
     * @param string|null $sealedAuthRequestId the identifier itself, sealed, for a client this provider has to call back with it (§10.2); null for a client that only polls, which is then the only holder of it
     * @param string|null $sealedNotificationToken the token such a client sent to recognise that call (§7.1), sealed the same way
     * @param RequestContext $requestedFrom where the client asked from, which the approval page shows (BCP 10027 §5.2)
     * @param int $interval the seconds between two polls the response announced, at least one (§7.3)
     *
     * @throws InvalidArgumentException when the record does not hold together
     */
    public function __construct(
        public readonly string $authRequestIdHash,
        public readonly Uuid $grantId,
        public readonly Client $client,
        public readonly ?User $user,
        public readonly Scopes $scopes,
        public readonly ?ResourceIndicators $resources,
        public readonly ?BindingMessage $bindingMessage,
        public readonly array $acrValues,
        public readonly ?string $sealedAuthRequestId,
        public readonly ?string $sealedNotificationToken,
        public readonly RequestContext $requestedFrom,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        int $interval = self::DEFAULT_INTERVAL,
    ) {
        if (! DrawnSecret::isDigest($authRequestIdHash)) {
            throw new InvalidArgumentException('A backchannel authentication request is stored as the hex SHA-256 of its auth_req_id.');
        }
        if ($user !== null && ! $user->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('A backchannel authentication request names a user of the tenant of its client.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A backchannel authentication request expires after it was asked for.');
        }
        if ($interval < 1) {
            throw new InvalidArgumentException('A backchannel authentication request announces a polling interval of at least one second (CIBA Core section 7.3).');
        }
        $this->interval = $interval;
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * What the request asks of the authentication of whoever answers it (CIBA Core §7.1, decision 0010).
     * It is voluntary and never a condition: §7.1 takes "acr_values" and takes no "claims", so this flow
     * has no essential form of the demand at all, and the "acr" of the tokens says what the session that
     * approved actually proved (OIDC Core §5.5.1.1).
     */
    public function requestedAuthenticationContext(): AuthenticationContextRequest
    {
        return new AuthenticationContextRequest($this->acrValues);
    }

    /**
     * CIBA Core §7.3: a positive number of seconds, rounded up so that the client is never told a
     * lifetime longer than the one the record has.
     *
     * @return positive-int
     */
    public function expiresIn(DateTimeImmutable $now): int
    {
        return max(1, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }

    public function belongsTo(Client $client): bool
    {
        return $this->clientId === $client->registration->clientId && $this->tenant->equals($client->tenant);
    }

    /**
     * CIBA Core §7.1: the request named its user, and that user is the only one who may answer it. A
     * request that named nobody is answered by nobody.
     */
    public function mayBeAnsweredBy(User $user): bool
    {
        return $this->user !== null && $this->user->id->equals($user->id) && $user->tenant->equals($this->tenant);
    }

    public function isAnswered(): bool
    {
        return $this->approvedAt !== null || $this->deniedAt !== null;
    }

    public function isApproved(): bool
    {
        return $this->approvedAt !== null;
    }

    public function isDenied(): bool
    {
        return $this->deniedAt !== null;
    }

    /**
     * CIBA Core §10.1: the user said yes, on a page of this provider, signed in as the one the request
     * named. The session they said it with, and the class it had proven then, are what every token of
     * this grant will descend from.
     *
     * @throws InvalidArgumentException when the session is not the one of the user this request named
     * @throws LogicException when the request was answered already; whoever answers reads isAnswered() first
     */
    public function approve(AuthenticationSession $session, AuthenticationSnapshot $authentication, DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        if (! $this->mayBeAnsweredBy($session->user)) {
            throw new InvalidArgumentException('A backchannel authentication request is approved by the user it named, with a session of its own tenant.');
        }
        $this->session = $session;
        $this->authentication = $authentication;
        $this->approvedAt = $now;
    }

    /**
     * CIBA Core §11: the user said no, and the client learns "access_denied".
     *
     * @throws LogicException when the request was answered already
     */
    public function deny(DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        $this->deniedAt = $now;
    }

    /**
     * CIBA Core §11: whether the client polled sooner than the interval it was given, in which case it is
     * told "slow_down" and the interval grows by five seconds, for that request and every one after it,
     * which is what the client is told to do with it. Every poll is recorded, the refused ones included:
     * asking again does not buy a faster answer.
     */
    public function polledTooSoon(DateTimeImmutable $now): bool
    {
        $last = $this->lastPolledAt;
        $this->lastPolledAt = $now;
        if ($last === null || ($now->getTimestamp() - $last->getTimestamp()) >= $this->interval) {
            return false;
        }
        $this->interval += self::INTERVAL_INCREASE;

        return true;
    }

    public function clientHolder(): object
    {
        return $this;
    }

    protected function nameOfRecord(): string
    {
        return 'A backchannel authentication request';
    }

    protected function readerThatChecks(): string
    {
        return 'the backchannel authentication grant';
    }

    /**
     * @throws LogicException
     */
    private function assertUnanswered(): void
    {
        if ($this->isAnswered()) {
            throw new LogicException('A backchannel authentication request is answered once; the page that answers it reads isAnswered() first.');
        }
    }
}
