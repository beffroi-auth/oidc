<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\Claims\OpenedSubjectIdentifierInterface;
use Beffroi\Oidc\Domain\Claims\PairwiseSubject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use function hash;
use Psr\Clock\ClockInterface;
use SensitiveParameter;
use function sprintf;

/**
 * Each identifier is recorded: the row is the way back from a "sub" to its user.
 */
final readonly class OpenedPairwiseSubjectIdentifier implements OpenedSubjectIdentifierInterface
{
    /**
     * @param non-empty-string $salt
     */
    public function __construct(
        private Tenant $tenant,
        private SectorIdentifier $sector,
        #[SensitiveParameter]
        private string $salt,
        private PairwiseSubjectRepositoryInterface $assigned,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
    ) {
    }

    public function subjectOf(User $user): Subject
    {
        if (! $user->tenant->equals($this->tenant)) {
            throw new LogicException(sprintf(
                'A user of the tenant "%s" has no identifier computed with the salt of the tenant "%s".',
                $user->tenant->slug,
                $this->tenant->slug,
            ));
        }
        $subject = $this->identifier($user);
        $this->assigned->record(new PairwiseSubject($this->uuids->timeOrdered(), $user, $this->sector, $subject, $this->clock->now()));

        return $subject;
    }

    /**
     * OIDC Core §8.1
     */
    private function identifier(User $user): Subject
    {
        $digest = hash('sha256', $this->sector->host . $user->subject->value . $this->salt, true);

        return new Subject(Base64Url::encode($digest));
    }
}
