<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Ciba;

use function array_find;
use DateTimeImmutable;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\SecretSealerInterface;
use Heidi\Oidc\Application\Consent\ConsentGranting;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Ciba\NotifiesTheClientInterface;
use Heidi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Heidi\Oidc\Domain\Interaction\StepUp;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function hash_equals;
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * What the page where a user answers a backchannel request asks of the provider (CIBA Core §10.1, BCP
 * 10027 §5.2): the requests waiting for that user, and the two answers they can give each of them.
 *
 * A user is shown the requests made for them and no others, and there is no code to type and no link to
 * follow: the requests are found by who is signed in, so nothing that reached the user from outside can
 * carry them to an approval (BCP 10027 §5.2). What a request of somebody else is, is nothing: it is not
 * in the list and it is not answerable, signed in or not.
 *
 * Approving is granting an authorization of the ordinary kind: the consent is recorded where a consent is
 * recorded, the session is the one the browser holds, and what that session had proven is frozen on the
 * record, so the tokens the client comes for descend from the approval.
 *
 * What the client asked the authentication to reach is answered here and nowhere else (§7.1, decision
 * 0010): a session that proves none of the requested classes, when a credential of that user would, owes
 * one more proof before it may approve, and the page asks for it. The class frozen on the record is the
 * requested one the session satisfies, and the one the session has otherwise; it is never the one the
 * request asked for.
 *
 * A client that registered to be called back is told that the request is over, whichever way it was
 * answered, and told nothing else: what the answer was it reads at the token endpoint.
 */
final readonly class BackchannelApproval
{
    public function __construct(
        private BackchannelAuthenticationRecordRepositoryInterface $records,
        private ConsentGranting $consents,
        private ApprovalAuthenticationRequirement $authentication,
        private SecretSealerInterface $sealer,
        private EventDispatcherInterface $events,
        private ClockInterface $clock,
    ) {
    }

    /**
     * The requests made for this user that are still waiting for an answer, oldest first.
     *
     * @return list<BackchannelAuthenticationRecord>
     */
    public function awaitingAnAnswerBy(User $user): array
    {
        return $this->records->awaitingAnAnswerBy($user, $this->clock->now());
    }

    /**
     * The one request of that list this handle names, null when it names none of them. The handle is
     * looked for among the requests that user may answer and never in the store: what somebody may answer
     * is decided once, by who they are, and a handle that named a request of somebody else would have to
     * be refused a second time somewhere.
     */
    public function awaitingAnAnswerFrom(User $user, string $authRequestIdHash): ?BackchannelAuthenticationRecord
    {
        return array_find(
            $this->awaitingAnAnswerBy($user),
            static fn (BackchannelAuthenticationRecord $record): bool => hash_equals($record->authRequestIdHash, $authRequestIdHash),
        );
    }

    /**
     * What one more authentication of this user would have to add before they may approve this request
     * (§7.1, decision 0010), null when nothing is owed. It is read by the page before it offers the
     * answer, and it is what approve() refuses to be called without.
     */
    public function stepUpFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): ?StepUp
    {
        return $this->authentication->stepUpFor($record, $session);
    }

    /**
     * CIBA Core §10.1: the user said yes, on a page of this provider, signed in as the one the request
     * named. The client learns it at its next poll, and at once when it registered to be told.
     *
     * @throws InvalidArgumentException when the session is not the one of the user the request named
     * @throws LogicException when the request was answered already, which awaitingAnAnswerBy() tells
     *                        first, and when the session still owes a proof the request asked for, which
     *                        stepUpFor() tells first
     */
    public function approve(BackchannelAuthenticationRecord $record, AuthenticationSession $session, RequestContext $context): void
    {
        if ($this->authentication->stepUpFor($record, $session) !== null) {
            throw new LogicException('A backchannel authentication request is approved by a session that proves what it asked for; the page that answers it reads stepUpFor() first.');
        }
        $now = $this->clock->now();
        // RFC 9396 §2 is not read at the endpoint this record was drawn at, so there is no detail to agree to
        $this->consents->grant($session, $record->client, $record->scopes, null, $context, $now);
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $this->authentication->classFor($record, $session)), $now);
        $this->records->save($record);
        $this->tellTheClient($record, $context, $now);
    }

    /**
     * CIBA Core §11: the user said no, and the client learns "access_denied". A refusal is an answer and
     * ends the request; nobody is asked twice about the same one.
     *
     * @throws LogicException when the request was answered already
     */
    public function deny(BackchannelAuthenticationRecord $record, RequestContext $context): void
    {
        $now = $this->clock->now();
        $record->deny($now);
        $this->records->save($record);
        $this->tellTheClient($record, $context, $now);
    }

    /**
     * CIBA Core §10.2: the identifier of the request, to the endpoint the client registered, with the
     * token it sent. Minting the word is here, carrying it is not (architecture §5.6): a client that
     * cannot be reached holds no approval up, and it would find the same answer by polling.
     */
    private function tellTheClient(BackchannelAuthenticationRecord $record, RequestContext $context, DateTimeImmutable $now): void
    {
        $registration = $record->client->registration;
        $endpoint = $registration->backchannelClientNotificationEndpoint;
        $sealedAuthRequestId = $record->sealedAuthRequestId;
        $sealedNotificationToken = $record->sealedNotificationToken;
        if (
            ! $registration->backchannelTokenDeliveryMode instanceof NotifiesTheClientInterface
            || $endpoint === null
            || $sealedAuthRequestId === null
            || $sealedNotificationToken === null
        ) {
            return;
        }
        $this->events->dispatch(new BackchannelRequestAnswered(
            $now,
            $record->tenant,
            $registration->clientId,
            $endpoint,
            $this->sealer->unseal($record->tenant, $sealedAuthRequestId),
            $this->sealer->unseal($record->tenant, $sealedNotificationToken),
            $context,
        ));
    }
}
