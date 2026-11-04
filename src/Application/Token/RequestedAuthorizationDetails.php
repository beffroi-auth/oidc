<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidAuthorizationDetailsException;
use Beffroi\Oidc\Port\AuthorizationDetailsReaderInterface;

/**
 * RFC 9396 §7
 */
final readonly class RequestedAuthorizationDetails
{
    public function __construct(
        private AuthorizationDetailsReaderInterface $authorizationDetailTypes,
    ) {
    }

    /**
     * @throws InvalidAuthorizationDetailsException when it asks for a detail the authorization does not carry
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
