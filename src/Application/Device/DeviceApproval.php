<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Device;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Consent\ConsentGranting;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Claims\ClaimNames;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Domain\Device\UserCode;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * RFC 8628 §3.3, §5.1
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
     * Null for an unknown, expired, answered, spent or foreign code alike, so a random guess learns nothing more.
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
     * @throws LogicException when the request was answered already
     */
    public function approve(DeviceAuthorizationRecord $record, AuthenticationSession $session, RequestContext $context): void
    {
        $now = $this->clock->now();
        // The device authorization endpoint reads no authorization details and no claim asked for by name.
        $this->consents->grant($session, $record->client, $record->scopes, null, new ClaimNames(), $context, $now);
        $record->approve($session, AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()), $now);
        $this->records->save($record);
    }

    /**
     * RFC 8628 §3.5
     *
     * @throws LogicException when the request was answered already
     */
    public function deny(DeviceAuthorizationRecord $record): void
    {
        $record->deny($this->clock->now());
        $this->records->save($record);
    }
}
