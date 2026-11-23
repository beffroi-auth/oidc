<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Oidc\Domain\Client\Client;
use SensitiveParameter;

/**
 * OIDC Core §3.1.2.1, CIBA Core §7.1
 */
final readonly class UsernameLoginHint implements HintShownAsSentInterface
{
    public const string PARAMETER = 'login_hint';

    public function __construct(
        private UserRepositoryInterface $users,
    ) {
    }

    public function parameterName(): string
    {
        return self::PARAMETER;
    }

    public function userNamedBy(Client $client, #[SensitiveParameter] string $value): ?User
    {
        return $this->users->findByUsername($client->tenant, $value);
    }

    public function shownAsSent(#[SensitiveParameter] string $value): string
    {
        return $value;
    }
}
