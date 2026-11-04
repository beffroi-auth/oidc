<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;

/**
 * RFC 9396 §2
 */
final readonly class RequestedAuthorizationDetails
{
    public function __construct(
        private AuthorizationDetailsReaderInterface $authorizationDetailTypes,
    ) {
    }

    /**
     * @throws InvalidAuthorizationDetailsException
     */
    public function of(Client $client, ?string $json): ?AuthorizationDetails
    {
        if ($json === null) {
            return null;
        }
        try {
            $details = $this->authorizationDetailTypes->fromJson($json);
        } catch (InvalidArgumentException $exception) {
            throw InvalidAuthorizationDetailsException::notWhatItMustBe(true, $exception);
        }
        if (! $client->registration->allowsAuthorizationDetails($details)) {
            throw InvalidAuthorizationDetailsException::notRegistered(true);
        }

        return $details;
    }
}
