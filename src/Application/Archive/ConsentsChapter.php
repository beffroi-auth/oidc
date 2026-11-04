<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Archive;

use Beffroi\Core\Domain\Archive\ArchivedFacts;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ArchiveChapterInterface;
use Beffroi\Oidc\Port\ActiveConsentsInterface;

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
