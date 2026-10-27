<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Claims;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UuidGeneratorInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Port\PairwiseSaltInterface;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Beffroi\Oidc\Port\SubjectIdentifierKindInterface;
use Psr\Clock\ClockInterface;

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
 *
 * An identifier is assigned in two steps (SubjectIdentifierOpenerInterface): the client is opened, which reads
 * its sector and unseals the salt of its tenant under the KMS, and the identifier of a user is then computed from
 * what was opened (OpenedPairwiseSubjectIdentifier), asking nothing of the KMS. A grant that spends what the
 * request presented has the client opened when its response is addressed, before the spending (architecture
 * §4.5); resolve() runs both steps at once.
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
        return $this->open($client)->subjectOf($user);
    }

    /**
     * The sector of the client and the salt of its tenant, read now: the salt is the step that asks the KMS.
     */
    public function open(Client $client): OpenedPairwiseSubjectIdentifier
    {
        $sector = $this->sectors->sectorOf($client->registration);

        return new OpenedPairwiseSubjectIdentifier(
            $client->tenant,
            $sector,
            $this->salts->saltOf($client->tenant),
            $this->assigned,
            $this->uuids,
            $this->clock,
        );
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
}
