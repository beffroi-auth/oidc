<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

use function base64_encode;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function preg_match;
use function random_bytes;
use function rtrim;
use function strtr;

/**
 * An authorization request parked while the user logs in and consents (architecture §4.3). The identifier
 * is 256 random bits and the bundle binds it to the browser session; an interaction is completed once.
 */
final class Interaction
{
    /**
     * 256 bits, base64url without padding.
     */
    private const string ID_PATTERN = '/^[A-Za-z0-9_-]{43}$/';

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    public private(set) ?AuthenticationSession $session = null;

    public private(set) ?Consent $consent = null;

    public private(set) ?DateTimeImmutable $completedAt = null;

    /**
     * @param string|null $locale the language of the pages of this interaction (architecture §5.7)
     * @param string|null $requestUriHash the pushed authorization request this one was started from
     *                                    (RFC 9126 §4), null when the request was not pushed; the
     *                                    reference is spent when this interaction grants, so that a
     *                                    request nobody has answered yet can be visited again
     */
    public function __construct(
        public readonly string $id,
        public readonly Tenant $tenant,
        public readonly AuthorizationRequest $request,
        public readonly ?string $locale,
        public readonly DateTimeImmutable $createdAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly ?string $requestUriHash = null,
    ) {
        if (preg_match(self::ID_PATTERN, $id) !== 1) {
            throw new InvalidArgumentException('An interaction identifier is 256 bits in base64url, see generateId().');
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

    public static function generateId(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
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
}
