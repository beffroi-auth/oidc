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
 * An "id_token_hint" read as what it is: an ID token this provider issued to this very client, whose
 * "sub" names the user (CIBA Core §7.1). It is the hint §15 recommends above every other, the client
 * naming the user by an identifier it was given here and that says nothing anywhere else.
 *
 * A token that was not issued here, or was issued to another client, is not a hint that names nobody: it
 * is a request that is wrong about what it carries, and it is refused as such. The token is read exactly
 * where every other ID token this provider takes back is read, against the keys of the tenant; "exp" is
 * not looked at, a hint describing a past sign-in being the ordinary case. Its "sub" is read for the client
 * that sent it and never as a key of a row (OIDC Core §8), the token having been written for that client.
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
