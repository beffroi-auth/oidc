<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba\Hint;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Application\Authorization\IdTokenHintVerifier;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Port\PresentedSubjectReaderInterface;
use SensitiveParameter;

/**
 * CIBA Core §7.1
 */
final readonly class IdTokenUserHint implements UserHintInterface
{
    public const string PARAMETER = 'id_token_hint';

    private const string NOT_FOR_CLIENT = 'The id_token_hint parameter is not an ID token issued to this client.';

    public function __construct(
        private IdTokenHintVerifier $hints,
        private PresentedSubjectReaderInterface $subjects,
    ) {
    }

    public function parameterName(): string
    {
        return self::PARAMETER;
    }

    public function userNamedBy(Client $client, #[SensitiveParameter] string $value): ?User
    {
        $hint = $this->hints->read($client->tenant, $value, false);
        if (! $hint->isFor($client->registration->clientId)) {
            throw new InvalidRequestException(self::NOT_FOR_CLIENT);
        }

        return $this->subjects->findUser($client, $hint->subject);
    }
}
