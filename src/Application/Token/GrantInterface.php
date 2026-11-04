<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Oidc\Application\Client\AuthenticatedClient;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Token\IssuedTokens;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\OAuth2Exception;

/**
 * Called once the client is authenticated and registered for this grant type.
 */
interface GrantInterface
{
    public function grantType(): GrantTypeName;

    /**
     * @throws OAuth2Exception an error of RFC 6749 §5.2
     * @throws ClientKeysUnavailableException before anything the request presented is spent
     * @throws KmsUnavailableException before anything the request presented is spent
     */
    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens;
}
