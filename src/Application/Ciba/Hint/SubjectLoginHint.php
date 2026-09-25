<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Ciba\Hint;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Port\UserRepositoryInterface;
use Heidi\Oidc\Application\Ciba\UserHintInterface;
use Heidi\Oidc\Domain\Client\Client;
use SensitiveParameter;

/**
 * A "login_hint" read as the "sub" this provider issues (CIBA Core §7.1, §15). It is the identifier the
 * client already has of that user and the one §15 asks for in place of a static global one: a telephone
 * number or an email address in a login hint is a value that says who somebody is everywhere, and this
 * one says it here and to this provider only.
 *
 * A value that is not a subject at all names nobody, exactly as a subject that belongs to nobody does:
 * the two answers are the same answer.
 */
final readonly class SubjectLoginHint implements UserHintInterface
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
        try {
            $subject = new Subject($value);
        } catch (InvalidArgumentException) {
            return null;
        }

        return $this->users->findBySubject($client->tenant, $subject);
    }
}
