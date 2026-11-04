<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * RFC 9068 §2.2
 */
final readonly class ClientSubject
{
    /**
     * @throws InvalidArgumentException when the identifier of the client is not one a subject can be
     */
    public static function of(Client $client): Subject
    {
        return self::ofIdentifier($client->registration->clientId);
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function ofIdentifier(string $clientId): Subject
    {
        try {
            return new Subject($clientId);
        } catch (CoreInvalidArgumentException $exception) {
            throw new InvalidArgumentException(sprintf(
                'The identifier of the client "%s" cannot be the "sub" of a token it holds for itself (OIDC Core section 2).',
                $clientId,
            ), previous: $exception);
        }
    }
}
