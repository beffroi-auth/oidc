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
 * OIDC Core §8.1 for one client, opened: the sector it is of and the salt of its tenant, read when the client was
 * opened (PairwiseSubjectIdentifierResolver), so that the identifier of a user is computed here asking nothing of
 * the KMS. The salt stays in memory for as long as this does and is never handed out: what leaves is the value
 * the identifier is hashed into.
 *
 * Each identifier assigned is recorded, as the resolver records it, because that row is the way back from a "sub"
 * to its user.
 */
final readonly class OpenedPairwiseSubjectIdentifier implements OpenedSubjectIdentifierInterface
{
    /**
     * @param non-empty-string $salt the salt of that tenant, opened
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
     * OIDC Core §8.1: the SHA-256 of the sector, the local account identifier and the salt, written in
     * base64url as every other value this provider hands out is.
     */
    private function identifier(User $user): Subject
    {
        $digest = hash('sha256', $this->sector->host . $user->subject->value . $this->salt, true);

        return new Subject(Base64Url::encode($digest));
    }
}
