<?php

declare(strict_types=1);

namespace Heidi\Oidc\Bridge\InMemory;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Claims\PairwiseSubject;
use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Port\PairwiseSubjectRepositoryInterface;
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
