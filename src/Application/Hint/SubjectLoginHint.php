<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use SensitiveParameter;

/**
 * OIDC Core §3.1.2.1, CIBA Core §7.1, §15
 *
 * Read for the client that sent it (OIDC Core §8): a pairwise "sub" of another sector names nobody.
 */
final readonly class SubjectLoginHint implements UserHintInterface
{
    public const string PARAMETER = 'login_hint';

    public function __construct(
        private PresentedSubjectReaderInterface $subjects,
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

        return $this->subjects->findUser($client, $subject);
    }
}
