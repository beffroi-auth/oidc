<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Oidc\Port\DisclosuresOfAPersonInterface;
use function count;

final readonly class DisclosuresChapter implements ArchiveChapterInterface
{
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
