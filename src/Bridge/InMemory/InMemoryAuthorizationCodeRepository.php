<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use function array_find;
use function array_values;
use DateTimeImmutable;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\LoggedInClientsInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;

final class InMemoryAuthorizationCodeRepository implements
    AuthorizationCodeRepositoryInterface,
    CanRevokeGrantsByConsentInterface,
    LoggedInClientsInterface,
    RecordedGrantsInterface
{
    /**
     * @var array<string, AuthorizationCode> by code hash
     */
    private array $codes = [];

    public private(set) int $saves = 0;

    public function findByCodeHash(string $codeHash): ?AuthorizationCode
    {
        return $this->codes[$codeHash] ?? null;
    }

    public function findByGrantId(Uuid $grantId): ?AuthorizationCode
    {
        return array_find($this->codes, static fn (AuthorizationCode $code): bool => $code->grantId->equals($grantId));
    }

    public function consume(AuthorizationCode $code, DateTimeImmutable $now): bool
    {
        $stored = $this->codes[$code->codeHash] ?? null;
        if ($stored === null || $stored->isUsed()) {
            return false;
        }
        ++$this->saves;
        $stored->consume($now);

        return true;
    }

    /**
     * @return list<Client>
     */
    public function ofSession(Uuid $session): array
    {
        $clients = [];
        foreach ($this->codes as $code) {
            if ($code->isUsed() && $code->session->id->equals($session)) {
                $clients[$code->clientId] = $code->client;
            }
        }

        return array_values($clients);
    }

    /**
     * @return list<AuthorizationCode>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        $revoked = [];
        foreach ($this->codes as $code) {
            if ($code->isRevoked() || ! $consent->covers($code->session, $code->clientId)) {
                continue;
            }
            $code->revoke($now);
            $this->save($code);
            $revoked[] = $code;
        }

        return $revoked;
    }

    public function save(AuthorizationCode $code): void
    {
        ++$this->saves;
        $this->codes[$code->codeHash] = $code;
    }

    /**
     * @return list<AuthorizationCode>
     */
    public function all(): array
    {
        return array_values($this->codes);
    }
}
