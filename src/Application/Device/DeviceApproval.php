<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Device;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Application\Consent\ConsentGranting;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Domain\Device\UserCode;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * What the page an appliance sends its user to asks of the provider (RFC 8628 §3.3, BCP 10027 §2): the
 * request a code names, and the two answers a user can give it.
 *
 * A code that names nothing, a code past its lifetime, a code of another tenant and a code somebody has
 * already answered are one refusal and not four: whoever is typing learns that this code is worth nothing
 * and nothing else, so that a code tried at random teaches no more than it should (RFC 8628 §5.1). How
 * often one may be tried is the page's, which counts the entries it refuses.
 *
 * Approving is granting an authorization of the ordinary kind: the consent is recorded where a consent is
 * recorded, the session is the one the browser holds, and what that session had proven is frozen on the
 * record, so the tokens the client polls for descend from the approval.
 */
final readonly class DeviceApproval
{
    public function __construct(
        private DeviceAuthorizationRecordRepositoryInterface $records,
        private ConsentGranting $consents,
        private ClockInterface $clock,
    ) {
    }

    /**
     * The request awaiting an answer that this code names, null when there is none: unknown, expired,
     * answered, spent, or of another tenant.
     */
    public function awaitingAnAnswer(Tenant $tenant, string $typedCode): ?DeviceAuthorizationRecord
    {
        $normalized = UserCode::normalize($typedCode);
        if (! UserCode::isWellFormed($normalized)) {
            return null;
        }
        $record = $this->records->findByUserCodeHash(UserCode::hashOf($normalized));
        if ($record === null || ! $record->tenant->equals($tenant)) {
            return null;
        }
        if ($record->isExpired($this->clock->now()) || $record->isAnswered() || $record->isUsed()) {
            return null;
        }

        return $record;
    }

    /**
     * RFC 8628 §3.3: the user said yes, on a page of this provider, signed in. The client learns it at its
     * next poll.
     *
     * @throws LogicException when the request was answered already, which awaitingAnAnswer() tells first
     */
    public function approve(DeviceAuthorizationRecord $record, AuthenticationSession $session, RequestContext $context): void
    {
        $now = $this->clock->now();
        // RFC 9396 §2 is not read at the endpoint this record was drawn at, so there is no detail to agree to
        $this->consents->grant($session, $record->client, $record->scopes, null, $context, $now);
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()), $now);
        $this->records->save($record);
    }

    /**
     * RFC 8628 §3.5: the user said no, and the client learns "access_denied". A refusal is an answer and
     * ends the request; nobody is asked twice about the same code.
     *
     * @throws LogicException when the request was answered already
     */
    public function deny(DeviceAuthorizationRecord $record): void
    {
        $record->deny($this->clock->now());
        $this->records->save($record);
    }
}
