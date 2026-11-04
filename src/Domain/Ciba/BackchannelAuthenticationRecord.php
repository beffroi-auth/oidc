<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthenticationContextRequest;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Symfony\Component\Uid\Uuid;
use function max;
use function sprintf;

/**
 * CIBA Core §7
 *
 * A hint that names nobody makes a record with no user, which expires unanswered: a client that names a stranger
 * learns no more than one whose user never answers (§13 "unknown_user_id").
 */
final class BackchannelAuthenticationRecord extends GrantRecord implements ResolvesItsClientInterface
{
    /**
     * CIBA Core §7.3
     */
    public const int DEFAULT_INTERVAL = 5;

    /**
     * CIBA Core §11
     *
     * Bounds the interval a request is made with, not what "slow_down" adds afterwards.
     */
    public const int MAX_INTERVAL = 30;

    /**
     * CIBA Core §11
     */
    public const int INTERVAL_INCREASE = 5;

    public readonly Tenant $tenant;

    public readonly string $clientId;

    /**
     * @var positive-int in seconds
     */
    public private(set) int $interval;

    public private(set) ?DateTimeImmutable $lastPolledAt = null;

    public private(set) ?DateTimeImmutable $approvedAt = null;

    public private(set) ?DateTimeImmutable $deniedAt = null;

    public private(set) ?AuthenticationSession $session = null;

    public private(set) ?AuthenticationSnapshot $authentication = null;

    /**
     * @param string $authRequestIdHash the hex SHA-256 of the auth_req_id
     * @param list<string> $acrValues in order of preference
     * @param string|null $sealedAuthRequestId null for a client that only polls
     * @param int $interval in seconds, from one to MAX_INTERVAL
     *
     * @throws InvalidArgumentException
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
        self::assertInterval($interval);
        $this->interval = $interval;
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * The interval a request may be made with, which the handler that makes them holds the interval it is
     * configured with to when it is built, and every record to when it is made.
     *
     * @phpstan-assert positive-int $interval
     *
     * @throws InvalidArgumentException when the interval is below one second or above MAX_INTERVAL
     */
    public static function assertInterval(int $interval): void
    {
        if ($interval < 1) {
            throw new InvalidArgumentException('A backchannel authentication request announces a polling interval of at least one second (CIBA Core section 7.3).');
        }
        if ($interval > self::MAX_INTERVAL) {
            throw new InvalidArgumentException(sprintf(
                'A backchannel authentication request announces a polling interval of at most %d seconds, a client respecting it (CIBA Core section 11); %d given.',
                self::MAX_INTERVAL,
                $interval,
            ));
        }
    }

    /**
     * Always voluntary: CIBA Core §7.1 takes "acr_values" and no "claims".
     */
    public function requestedAuthenticationContext(): AuthenticationContextRequest
    {
        return new AuthenticationContextRequest($this->acrValues);
    }

    /**
     * CIBA Core §7.3
     *
     * @return positive-int in seconds
     */
    public function expiresIn(DateTimeImmutable $now): int
    {
        return max(1, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }

    public function belongsTo(Client $client): bool
    {
        return $this->clientId === $client->registration->clientId && $this->tenant->equals($client->tenant);
    }

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
     * @throws InvalidArgumentException when the session is not of the user this request named
     * @throws LogicException when the request was answered already
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
     * @throws LogicException when the request was answered already
     */
    public function deny(DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        $this->deniedAt = $now;
    }

    /**
     * CIBA Core §11
     *
     * Records every poll, the refused ones included, and grows the interval when the poll came too soon.
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

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'bindingMessage' => new Sealed('backchannel_authentication_request'),
            'acrValues' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'sealedAuthRequestId' => new NoPersonalDatum(Reason::AN_ENVELOPE),
            'sealedNotificationToken' => new NoPersonalDatum(Reason::AN_ENVELOPE),
            'requestedFrom' => new Sealed('backchannel_authentication_request'),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'interval' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'lastPolledAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'approvedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'deniedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'authRequestIdHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'user' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
