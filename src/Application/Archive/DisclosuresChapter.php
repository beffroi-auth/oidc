<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use function count;

/**
 * What every application was given of this person, in the archive they ask for (issues #453 and #590): one
 * line per act that handed something over, with the client, the moment, and what left with it.
 *
 * It is the other half of what the journal says: the journal holds the act, this holds what the act gave,
 * and the two are read together by the person they name and the moment they share. Where the consents
 * chapter beside it answers what each application **may** obtain now, this answers what each one **did**
 * obtain, which is the question a person asks of a consent they have since taken back.
 *
 * It is a chapter of this module and not of the core, as the consents are: a scope is what the protocol
 * calls what a client may obtain.
 *
 * It is read in pages, as the journal is, the identifier of a row being a UUIDv7.
 */
final readonly class DisclosuresChapter implements ArchiveChapterInterface
{
    /**
     * How many rows one page reads, the bound the journal's chapter has and for the same reason.
     */
    public const int READ_AT_ONCE = 500;

    public function __construct(
        private DisclosuresOfAPersonInterface $disclosures,
    ) {
    }

    public function name(): string
    {
        return 'disclosures';
    }

    public function of(User $user): array
    {
        $lines = [];
        $after = null;
        do {
            $page = $this->disclosures->everyDisclosureTo($user, self::READ_AT_ONCE, $after);
            foreach ($page as $disclosure) {
                $lines[] = [
                    'client_id' => $disclosure->clientId,
                    'act' => $disclosure->act,
                    'handed_over_at' => ArchivedFacts::moment($disclosure->handedOverAt),
                    'scopes' => $disclosure->scopes->values(),
                    'claims' => $disclosure->claims?->names(),
                    'authorization_details' => $disclosure->details?->toClaim(),
                    'token_shape' => $disclosure->tokenShape,
                ];
                $after = $disclosure->id;
            }
        } while (count($page) === self::READ_AT_ONCE);

        return $lines;
    }
}
