<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;

/**
 * What the "authorization_details" parameter of an authorization request must be (RFC 9396 §2), judged
 * against the client that sends it, the counterpart of the class of the same name that narrows it at the
 * token endpoint against the grant being spent (Application\Token\RequestedAuthorizationDetails).
 */
final readonly class RequestedAuthorizationDetails
{
    public function __construct(
        private AuthorizationDetailsReaderInterface $authorizationDetailTypes,
    ) {
    }

    /**
     * What this request asks for beyond its scopes, a JSON array of objects each naming its type. The
     * types are the ones the provider is wired with, each validating its own members, and what a client
     * may ask for is the closed list of its registration (§11), as every other list of a client is. A
     * malformed array, an object naming no type, a type nobody serves and a type the client is not
     * registered for are all "invalid_authorization_details" (§5), which goes back to the redirect URI as
     * every refusal of this stage does.
     *
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
