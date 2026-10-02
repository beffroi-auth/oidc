<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\InMemory;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Claims\PairwiseSubject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use function sprintf;

/**
 * For tests and for the examples: nothing here survives the process.
 */
final class InMemoryPairwiseSubjectRepository implements PairwiseSubjectRepositoryInterface
{
    /**
     * @var array<string, PairwiseSubject>
     */
    private array $assigned = [];

    public function findUser(Tenant $tenant, SectorIdentifier $sector, Subject $subject): ?User
    {
        return ($this->assigned[self::key($tenant, $sector, $subject)] ?? null)?->user;
    }

    public function record(PairwiseSubject $assigned): void
    {
        $key = self::key($assigned->tenant, $assigned->sector, $assigned->subject);
        $this->assigned[$key] ??= $assigned;
    }

    private static function key(Tenant $tenant, SectorIdentifier $sector, Subject $subject): string
    {
        return sprintf('%s|%s|%s', $tenant->id->toRfc4122(), $sector->host, $subject->value);
    }
}
