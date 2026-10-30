<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Oidc\Port\ActiveConsentsInterface;

/**
 * What a person has agreed to, in the archive they ask for (issue #453): one line per client that may
 * obtain something about them, what it was granted and when.
 *
 * It is a chapter of this module and not of the core, which is the reason a chapter is a port at all: the
 * core knows no protocol, and a consent is what OAuth calls the permission a person gave a client. A
 * module added to this provider brings the chapters of what it holds, and the use case that assembles the
 * document is not edited.
 */
final readonly class ConsentsChapter implements ArchiveChapterInterface
{
    public function __construct(
        private ActiveConsentsInterface $consents,
    ) {
    }

    public function name(): string
    {
        return 'consents';
    }

    public function of(User $user): array
    {
        $lines = [];
        foreach ($this->consents->activeOf($user) as $consent) {
            $lines[] = [
                'client_id' => $consent->clientId,
                'client_name' => $consent->client->registration->presentation->name,
                'scopes' => $consent->scopes->values(),
                'authorization_details' => $consent->authorizationDetails?->toClaim(),
                'claims' => $consent->claims->all,
                'granted_at' => ArchivedFacts::moment($consent->grantedAt),
            ];
        }

        return $lines;
    }
}
