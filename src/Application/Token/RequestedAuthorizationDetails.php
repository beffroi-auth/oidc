<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;

/**
 * What a token request asks its access token to carry beyond its scopes (RFC 9396 §7). Every grant that
 * spends an authorization reads it the same way, so it is read here once: a request that asks for no
 * detail takes the details of the authorization it spends, one that asks for a subset of them is served
 * that subset, and one that asks for anything else is refused with "invalid_authorization_details".
 *
 * Narrowing never widens: what the details carry was agreed to on a page, against what the client
 * registered, and a token request is not another chance to ask. It is the counterpart of
 * RequestedResources, and it refuses the same way for the same reason.
 */
final readonly class RequestedAuthorizationDetails
{
    public function __construct(
        private AuthorizationDetailsReaderInterface $authorizationDetailTypes,
    ) {
    }

    /**
     * @param AuthorizationDetails|null $granted the details of the authorization being spent, null when it carries none
     *
     * @throws InvalidAuthorizationDetailsException when the parameter is not an array of details of types
     *                                             this provider serves, or asks for a detail the
     *                                             authorization does not carry
     *
     * @return AuthorizationDetails|null null when the request narrows nothing
     */
    public function of(RequestParameters $request, ?AuthorizationDetails $granted): ?AuthorizationDetails
    {
        $json = $request->optional('authorization_details');
        if ($json === null) {
            return null;
        }
        try {
            $requested = $this->authorizationDetailTypes->fromJson($json);
        } catch (InvalidArgumentException $exception) {
            throw InvalidAuthorizationDetailsException::notWhatItMustBe(previous: $exception);
        }
        if ($granted === null || ! $granted->covers($requested)) {
            throw InvalidAuthorizationDetailsException::notGranted();
        }

        return $requested;
    }
}
