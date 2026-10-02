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
 * A "login_hint" read as the "sub" this provider issues (OIDC Core §3.1.2.1, CIBA Core §7.1, §15). It is
 * the identifier the client already has of that user and the one §15 asks for in place of a static global
 * one: a telephone number or an email address in a login hint is a value that says who somebody is
 * everywhere, and this one says it here and to this provider only. It is also the one value this provider
 * writes itself, in the "login_hint" of a login it begins at the client (OIDC Core §4), so reading it back
 * is what makes that hint worth carrying.
 *
 * A value that is not a subject at all names nobody, exactly as a subject that belongs to nobody does:
 * the two answers are the same answer. The hint is read for the client that sent it and never as a key of
 * a row (OIDC Core §8): a "sub" a client of another sector holds names nobody here, which is what makes a
 * pairwise identifier worth having.
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
