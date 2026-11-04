<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function array_find;
use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\SecretSealerInterface;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Beffroi\Oidc\Domain\Ciba\NotifiesTheClientInterface;
use Beffroi\Oidc\Domain\Event\BackchannelRequestAnswered;
use Beffroi\Oidc\Domain\Interaction\StepUp;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use function hash_equals;
use Beffroi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

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
     * @return list<BackchannelAuthenticationRecord> oldest first
     */
    public function awaitingAnAnswerBy(User $user): array
    {
        return $this->records->awaitingAnAnswerBy($user, $this->clock->now());
    }

    /**
     * Looked for among this user's requests, never in the store: a handle cannot reach another user's request.
     */
    public function awaitingAnAnswerFrom(User $user, string $authRequestIdHash): ?BackchannelAuthenticationRecord
    {
        return array_find(
            $this->awaitingAnAnswerBy($user),
            static fn (BackchannelAuthenticationRecord $record): bool => hash_equals($record->authRequestIdHash, $authRequestIdHash),
        );
    }

    public function stepUpFor(BackchannelAuthenticationRecord $record, AuthenticationSession $session): ?StepUp
    {
        return $this->authentication->stepUpFor($record, $session);
    }

    /**
     * @throws InvalidArgumentException when the session is not the one of the user the request named
     * @throws LogicException when the request was answered already, or the session still owes a proof
     */
    public function approve(BackchannelAuthenticationRecord $record, AuthenticationSession $session, RequestContext $context): void
    {
        if ($this->authentication->stepUpFor($record, $session) !== null) {
            throw new LogicException('A backchannel authentication request is approved by a session that proves what it asked for; the page that answers it reads stepUpFor() first.');
        }
        $now = $this->clock->now();
        // The backchannel endpoint reads no authorization details and no claims by name: none to agree to.
        $this->consents->grant($session, $record->client, $record->scopes, null, new ClaimNames(), $context, $now);
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $this->authentication->classFor($record, $session)), $now);
        $this->records->save($record);
        $this->tellTheClient($record, $context, $now);
    }

    /**
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
     * CIBA Core §10.2
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
            $record->user?->subject,
            $endpoint,
            $this->sealer->unseal($record->tenant, $sealedAuthRequestId),
            $this->sealer->unseal($record->tenant, $sealedNotificationToken),
            $context,
        ));
    }
}
