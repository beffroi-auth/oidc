<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;

/**
 * An authorization request parked while the user logs in and consents.
 */
final class Interaction implements ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public readonly string $clientId;

    public private(set) ?AuthenticationSession $session = null;

    public private(set) ?Consent $consent = null;

    public private(set) ?DateTimeImmutable $completedAt = null;

    public function __construct(
        public readonly string $id,
        public readonly Tenant $tenant,
        public readonly AuthorizationRequest $request,
        public private(set) ?string $locale,
        public readonly DateTimeImmutable $createdAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?string $requestUriHash = null,
    ) {
        if (! DrawnSecret::isValue($id)) {
            throw new InvalidArgumentException('An interaction identifier is 256 bits in base64url, as every value this provider draws.');
        }
        if (! $request->client->belongsTo($tenant)) {
            throw new InvalidArgumentException('An interaction serves a client of its own tenant.');
        }
        if ($locale === '') {
            throw new InvalidArgumentException('The locale of an interaction is either absent or non-empty.');
        }
        if ($expiresAt <= $createdAt) {
            throw new InvalidArgumentException('An interaction expires after it was created.');
        }
        $this->clientId = $request->client->registration->clientId;
    }

    /**
     * @throws InvalidArgumentException if the locale is empty
     */
    public function readIn(string $locale): void
    {
        if ($locale === '') {
            throw new InvalidArgumentException('The locale of an interaction is either absent or non-empty.');
        }
        $this->locale = $locale;
    }

    /**
     * A session of another user than the one a consent was recorded for drops that consent.
     */
    public function authenticate(AuthenticationSession $session, DateTimeImmutable $now): void
    {
        $this->assertResumable($now);
        if (! $session->tenant->equals($this->tenant)) {
            throw new InvalidArgumentException('An interaction is resumed with a session of its own tenant.');
        }
        if (! $session->isActive($now)) {
            throw new LogicException('An interaction is resumed with an active session.');
        }
        if ($this->consent !== null && ! $this->consent->user->id->equals($session->user->id)) {
            $this->consent = null;
        }
        $this->session = $session;
    }

    public function consent(Consent $consent, DateTimeImmutable $now): void
    {
        $this->assertResumable($now);
        if ($this->session === null) {
            throw new LogicException('A consent is recorded on an authenticated interaction.');
        }
        if (! $consent->isFor($this->session->user, $this->request->client)) {
            throw new InvalidArgumentException('A consent is recorded for the user of the session and the client of the request.');
        }
        if (! $consent->scopes->covers($this->request->scopes)) {
            throw new InvalidArgumentException('A consent recorded on an interaction covers every scope of the request.');
        }
        if (! $consent->coversAuthorizationDetails($this->request->authorizationDetails)) {
            throw new InvalidArgumentException('A consent recorded on an interaction covers every authorization detail of the request (RFC 9396 section 7).');
        }
        $this->consent = $consent;
    }

    public function complete(DateTimeImmutable $now): void
    {
        $this->assertResumable($now);
        $this->completedAt = $now;
    }

    public function isCompleted(): bool
    {
        return $this->completedAt !== null;
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    /**
     * Whether the latest proof of the session was given at or after the instant this interaction began.
     */
    public function sawTheLoginOf(AuthenticationSession $session): bool
    {
        return $session->authenticatedAt() >= $this->createdAt;
    }

    /**
     * @throws InteractionCompletedException
     * @throws InteractionExpiredException
     */
    public function assertResumable(DateTimeImmutable $now): void
    {
        if ($this->completedAt !== null) {
            throw new InteractionCompletedException($this->id);
        }
        if ($this->isExpired($now)) {
            throw new InteractionExpiredException($this->id);
        }
    }

    public function clientHolder(): object
    {
        return $this->request;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'locale' => new NoPersonalDatum(Reason::THE_LANGUAGE_ASKED_FOR),
            'createdAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'completedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'requestUriHash' => new NoPersonalDatum(Reason::HASHED),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'consent' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
