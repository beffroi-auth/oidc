<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Claims;

use function base64_encode;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\UuidGeneratorInterface;
use Heidi\Oidc\Domain\Claims\PairwiseSubject;
use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Port\PairwiseSaltInterface;
use Heidi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Heidi\Oidc\Port\SectorIdentifiersInterface;
use Heidi\Oidc\Port\SubjectIdentifierKindInterface;
use function hash;
use Psr\Clock\ClockInterface;
use function rtrim;
use function strtr;

/**
 * OIDC Core §8.1 "pairwise": each sector sees a user under an identifier of its own, and no two sectors can
 * find out they are looking at the same person by comparing the strings they hold. It is the kind a provider
 * serving an ecosystem of relying parties it did not choose exists to offer.
 *
 * The value is the one §8.1 writes: the SHA-256 of the sector, the identifier the provider knows the user by
 * and the salt of the tenant, in base64url. It is computed and never drawn, so it is the same identifier
 * after a restore, after an import that keeps the subjects of decision 0002, and in every worker at once;
 * and it is reversible by nobody, the salt never leaving the deployment (PairwiseSaltInterface).
 *
 * What is written down is the way back. Hashing goes one way, so a "sub" a client presents cannot be turned
 * into a user by computing anything: the identifier assigned to a user for a sector is recorded the first
 * time a document is written for that sector, and read back from there. The write is synchronous because the
 * protocol needs its result in the same request as often as not, an access token issued at the token
 * endpoint being introspected at a resource of the provider a moment later, and it costs one statement that
 * does nothing when the row is already there.
 */
final readonly class PairwiseSubjectIdentifierResolver implements SubjectIdentifierKindInterface
{
    public const string SUBJECT_TYPE = 'pairwise';

    public function __construct(
        private SectorIdentifiersInterface $sectors,
        private PairwiseSaltInterface $salts,
        private PairwiseSubjectRepositoryInterface $assigned,
        private UuidGeneratorInterface $uuids,
        private ClockInterface $clock,
    ) {
    }

    public function subjectType(): string
    {
        return self::SUBJECT_TYPE;
    }

    public function resolve(User $user, Client $client): Subject
    {
        $sector = $this->sectors->sectorOf($client->registration);
        $subject = self::identifier($sector, $user, $this->salts->saltOf($user->tenant));
        $this->assigned->record(new PairwiseSubject($this->uuids->timeOrdered(), $user, $sector, $subject, $this->clock->now()));

        return $subject;
    }

    /**
     * The identifier is looked up in the sector of the client that presented it and in no other, which is
     * what makes the "sub" of one sector name nobody to a client of another.
     */
    public function findUser(Client $client, Subject $subject): ?User
    {
        try {
            $sector = $this->sectors->sectorOf($client->registration);
        } catch (InvalidArgumentException) {
            return null;
        }

        return $this->assigned->findUser($client->tenant, $sector, $subject);
    }

    /**
     * A client of this kind has a sector, and what says which one is what it registered, read through every
     * source the deployment wired (OIDC Core §8.1, CIBA Core §4). A client that registers redirection URIs
     * on several hosts and no "sector_identifier_uri", and a client that registers no redirection URI and
     * no "jwks_uri" either, name no sector, and both are refused here rather than served an identifier
     * computed from whichever value came first.
     */
    public function assertAssignable(ClientRegistration $registration): void
    {
        try {
            $this->sectors->sectorOf($registration);
        } catch (InvalidArgumentException $exception) {
            throw new InvalidClientMetadataException('sector_identifier_uri', null, $exception->getMessage(), $exception);
        }
    }

    /**
     * OIDC Core §8.1: the SHA-256 of the sector, the local account identifier and the salt, written in
     * base64url as every other value this provider hands out is.
     */
    private static function identifier(SectorIdentifier $sector, User $user, string $salt): Subject
    {
        $digest = hash('sha256', $sector->host . $user->subject->value . $salt, true);

        return new Subject(rtrim(strtr(base64_encode($digest), '+/', '-_'), '='));
    }
}
