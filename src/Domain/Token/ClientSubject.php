<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * What names a client where a subject is expected (RFC 9068 §2.2): the "sub" of an access token it holds
 * for itself, there being nobody else to name (RFC 6749 §4.4). Written once, because the issuers write it
 * into the token and the reading of a stored one writes it back, and the two name the same thing or the
 * provider does not recognise its own token.
 *
 * A client identifier may carry a space (RFC 6749 appendix A.1) and a subject may not (OIDC Core §2), so a
 * client named that way cannot act for itself; it is refused where a registration is read, and here as the
 * invariant behind it.
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
