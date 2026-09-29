<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Hint;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Domain\Client\Client;
use SensitiveParameter;

/**
 * A "login_hint" read as the name the user signs in with (OIDC Core §3.1.2.1, CIBA Core §7.1). It is what
 * a deployment whose clients know their users by that name wires in place of the subject one, and never
 * beside it: two ways of reading one parameter would be the search §7.1 does not ask for.
 *
 * CIBA Core §15 is the reason this is not the one wired by default: a name a user carries everywhere is
 * the static global identifier that section warns about, and what it costs is that a client learns
 * nothing it did not already know only when the name is one it already knew.
 */
final readonly class UsernameLoginHint implements UserHintInterface
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
}
