<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Device;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
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
use function sprintf;

/**
 * RFC 8628 §3.1, §3.2
 */
final class DeviceAuthorizationRecord extends GrantRecord implements ResolvesItsClientInterface
{
    /**
     * RFC 8628 §3.2
     */
    public const int DEFAULT_INTERVAL = 5;

    /**
     * The longest interval a request starts with; "slow_down" may raise it further.
     */
    public const int MAX_INTERVAL = 30;

    /**
     * RFC 8628 §3.5
     */
    public const int INTERVAL_INCREASE = 5;

    public readonly Tenant $tenant;

    public readonly string $clientId;

    /**
     * @var positive-int
     */
    public private(set) int $interval;

    public private(set) ?DateTimeImmutable $lastPolledAt = null;

    public private(set) ?DateTimeImmutable $approvedAt = null;

    public private(set) ?DateTimeImmutable $deniedAt = null;

    public private(set) ?AuthenticationSession $session = null;

    public private(set) ?AuthenticationSnapshot $authentication = null;

    /**
     * @throws InvalidArgumentException
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
            throw new InvalidArgumentException('A device authorization request announces a polling interval of at least one second (RFC 8628 section 3.2).');
        }
        if ($interval > self::MAX_INTERVAL) {
            throw new InvalidArgumentException(sprintf(
                'A device authorization request announces a polling interval of at most %d seconds, a client respecting it (RFC 8628 section 3.5); %d given.',
                self::MAX_INTERVAL,
                $interval,
            ));
        }
    }

    /**
     * RFC 8628 §3.2
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
     * RFC 8628 §3.3
     *
     * @throws InvalidArgumentException when the session serves another tenant
     * @throws LogicException
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
     * RFC 8628 §3.5
     *
     * @throws LogicException
     */
    public function deny(DateTimeImmutable $now): void
    {
        $this->assertUnanswered();
        $this->deniedAt = $now;
    }

    /**
     * RFC 8628 §3.5
     *
     * Records every poll, a refused one included, and raises the interval when it came too soon.
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

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'userCodeHash' => new NoPersonalDatum(Reason::HASHED),
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'requestedFrom' => new Sealed('device_authorization_request'),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'interval' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'lastPolledAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'approvedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'deniedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'deviceCodeHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
