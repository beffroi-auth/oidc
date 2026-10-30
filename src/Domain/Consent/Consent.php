<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Consent;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * What a user agreed to let a client obtain about them (architecture §4.3). A new grant to the same client
 * supersedes the previous one, which is revoked.
 */
final class Consent implements ResolvesItsClientInterface, ClassifiedFieldsInterface
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    public private(set) ?DateTimeImmutable $revokedAt = null;

    /**
     * @param AuthorizationDetails|null $authorizationDetails what the user agreed to beyond the scopes
     *                                                        (RFC 9396 §2), null when they agreed to none
     * @param ClaimNames $claims the claims the user agreed to one by name, beyond what the scopes stand for
     *                           (OIDC Core §5.5), none when no request asked for one
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly User $user,
        public readonly Client $client,
        public readonly Scopes $scopes,
        public readonly DateTimeImmutable $grantedAt,
        public readonly ?AuthorizationDetails $authorizationDetails = null,
        public readonly ClaimNames $claims = new ClaimNames(),
    ) {
        if (! $client->belongsTo($user->tenant)) {
            throw new InvalidArgumentException('A consent binds a user and a client of the same tenant.');
        }
        $this->tenant = $user->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * The consent that supersedes this one when the user agrees to more: its scopes and the ones given,
     * its details and the ones given, its claims and the ones given, each once, from now; this one is
     * revoked. What a user agreed to is never taken back by a new agreement (architecture §4.3).
     *
     * @param AuthorizationDetails|null $authorizationDetails what was just agreed to beyond the scopes,
     *                                                        null when the request asked for none, which
     *                                                        leaves what this consent already carries
     * @param ClaimNames $claims what was just agreed to by name, none when the request asked for none
     */
    public function extendedWith(Scopes $scopes, ?AuthorizationDetails $authorizationDetails, ClaimNames $claims, Uuid $id, DateTimeImmutable $now): self
    {
        $this->revoke($now);

        return new self(
            $id,
            $this->user,
            $this->client,
            new Scopes([...$this->scopes->all, ...$scopes->all]),
            $now,
            self::merged($this->authorizationDetails, $authorizationDetails),
            $this->claims->with($claims),
        );
    }

    /**
     * What a consent carries once it has been given twice: both sets as one, each detail once, the ones
     * already held first (RFC 9396 §2). Either side may be nothing, a request that asks for no detail
     * taking nothing back from one that did.
     */
    private static function merged(?AuthorizationDetails $held, ?AuthorizationDetails $given): ?AuthorizationDetails
    {
        if ($held === null) {
            return $given;
        }

        return $given === null ? $held : $held->mergedWith($given);
    }

    public function isActive(): bool
    {
        return $this->revokedAt === null;
    }

    /**
     * The first revocation wins.
     */
    public function revoke(DateTimeImmutable $now): void
    {
        if ($this->revokedAt !== null) {
            return;
        }
        $this->revokedAt = $now;
    }

    /**
     * Whether what a session obtained from this provider for a client was obtained under this consent:
     * the same user, the same client. The one place the rule is written for the stores that answer what
     * a consent taken back reaches, a grant, a refresh token, an access token (architecture §4.3).
     */
    public function covers(AuthenticationSession $session, string $clientId): bool
    {
        return $this->coversUser($session->user, $clientId);
    }

    /**
     * The same rule where no session is known yet: a record a client drew for a user it named, waiting for
     * that user to answer (RFC 8628 §3.2, CIBA Core §7), is a grant this consent covers before anybody has
     * signed in for it.
     */
    public function coversUser(User $user, string $clientId): bool
    {
        return $this->clientId === $clientId && $user->id->equals($this->user->id);
    }

    /**
     * Whether this consent answers for a request asking for these details (RFC 9396 §7): every detail is
     * one the user has already agreed to, or the page asks again. A request that asks for none is covered
     * by every consent, there being nothing structured to agree to.
     */
    public function coversAuthorizationDetails(?AuthorizationDetails $details): bool
    {
        if ($details === null) {
            return true;
        }

        return $this->authorizationDetails !== null && $this->authorizationDetails->covers($details);
    }

    /**
     * Whether this consent answers for these claims asked for by name (OIDC Core §5.5): every one is a claim
     * the user has already agreed to by name, or the page asks again. Which claims the scopes it holds stand
     * for is what the wiring says and not this entity, so the caller has taken those out already.
     */
    public function coversClaims(ClaimNames $claims): bool
    {
        return $this->claims->covers($claims);
    }

    public function isFor(User $user, Client $client): bool
    {
        return $this->user->id->equals($user->id) && $this->client->equals($client);
    }

    public function clientHolder(): object
    {
        return $this;
    }

    /**
     * A permission one person gave one client: what was permitted, and the instants it was given and taken back at.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'claims' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'grantedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'revokedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'user' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
