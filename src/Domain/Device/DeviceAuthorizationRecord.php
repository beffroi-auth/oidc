<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Device;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Exception\LogicException;
use function max;

/**
 * What the provider keeps of a device authorization request (RFC 8628 §3.1, §3.2): the SHA-256 of the
 * device code the client polls with and of the user code the user types, the client the record is bound to,
 * and what the request asked for. Where the request came from is kept beside them, because the page that
 * asks the user to approve it says so (BCP 10027 §2): somebody who did not start anything must be able to
 * tell that they did not.
 *
 * It is a record and not a request: it outlives the request that created it, with a lifetime, a use and a
 * state of its own. Two things happen to it. The user answers it, once, yes or no; and the client spends
 * it, once, the record being read once as an authorization code is (RecordReadOnce). An answered record
 * that nobody spent stays until it expires, and a spent one stays so that the next presentation is told
 * from a device code nobody ever issued.
 *
 * The session the user answered with, and what that session had proven then, are frozen here: the tokens
 * the client polls for descend from the approval and not from whatever the session became afterwards
 * (architecture §4.6). The record is also the grant those tokens descend from (GrantRecord): this flow
 * writes no authorization code, and a resource of this provider asks of a token whether the grant behind
 * it is still alive.
 */
final class DeviceAuthorizationRecord extends GrantRecord implements ResolvesItsClientInterface
{
    /**
     * RFC 8628 §3.2: the seconds a client waits between two polls when the response names none.
     */
    public const int DEFAULT_INTERVAL = 5;

    /**
     * RFC 8628 §3.5: what "slow_down" adds to the interval, for that request and every one after it.
     */
    public const int INTERVAL_INCREASE = 5;

    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * RFC 8628 §3.5: the seconds the client is asked to wait between two polls, as this record has come
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
     * @param string $deviceCodeHash the hex SHA-256 of the device code (DrawnSecret)
     * @param string $userCodeHash see UserCode::hashOf()
     * @param Uuid $grantId the grant the tokens of this request will name
     * @param Scopes $scopes what the request asked for, among the ones the client registered
     * @param ResourceIndicators|null $resources what the access token will be addressed to (RFC 8707 §2), null when the request named none
     * @param RequestContext $requestedFrom where the appliance asked from, which the approval page shows (BCP 10027 §2)
     * @param int $interval the seconds between two polls the response announced, at least one (RFC 8628 §3.2)
     *
     * @throws InvalidArgumentException when the record does not hold together
     */
    public function __construct(
        public readonly string $deviceCodeHash,
        public readonly string $userCodeHash,
        public readonly Uuid $grantId,
        public readonly Client $client,
        public readonly Scopes $scopes,
        public readonly ?ResourceIndicators $resources,
        public readonly RequestContext $requestedFrom,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        int $interval = self::DEFAULT_INTERVAL,
    ) {
        if (! DrawnSecret::isDigest($deviceCodeHash)) {
            throw new InvalidArgumentException('A device authorization request is stored as the hex SHA-256 of its device code.');
        }
        if (! DrawnSecret::isDigest($userCodeHash)) {
            throw new InvalidArgumentException('A device authorization request is stored as the hex SHA-256 of its user code.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A device authorization request expires after it was asked for.');
        }
        if ($interval < 1) {
            throw new InvalidArgumentException('A device authorization request announces a polling interval of at least one second (RFC 8628 section 3.2).');
        }
        $this->interval = $interval;
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * RFC 8628 §3.2: a positive number of seconds, rounded up so that the client is never told a lifetime
     * longer than the one the record has.
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
     * RFC 8628 §3.3: the user said yes. The session they said it with, and the class it had proven then,
     * are what every token of this grant will descend from.
     *
     * @throws InvalidArgumentException when the session serves another tenant
     * @throws LogicException when the request was answered already; whoever answers reads isAnswered() first
     */
    public function approve(AuthenticationSession $session, AuthenticationSnapshot $authentication, DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        if (! $session->tenant->equals($this->tenant)) {
            throw new InvalidArgumentException('A device authorization request is approved with a session of its own tenant.');
        }
        $this->session = $session;
        $this->authentication = $authentication;
        $this->approvedAt = $now;
    }

    /**
     * RFC 8628 §3.5: the user said no, and the client learns "access_denied" at its next poll.
     *
     * @throws LogicException when the request was answered already
     */
    public function deny(DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        $this->deniedAt = $now;
    }

    /**
     * RFC 8628 §3.5: whether the client polled sooner than the interval it was given, in which case it is
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
        return 'A device authorization request';
    }

    protected function readerThatChecks(): string
    {
        return 'the device code grant';
    }

    /**
     * @throws LogicException
     */
    private function assertUnanswered(): void
    {
        if ($this->isAnswered()) {
            throw new LogicException('A device authorization request is answered once; the page that answers it reads isAnswered() first.');
        }
    }
}
