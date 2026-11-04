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
 * OIDC Core §8.1
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
     * Looked up in the client's own sector only, so a "sub" of one sector names nobody to a client of another.
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
     * OIDC Core §8.1, CIBA Core §4
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
