<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Token;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Token\IssuedTokens;
use Heidi\Oidc\Exception\OAuth2Exception;

/**
 * One grant type of the token endpoint (RFC 6749 §4.1.3, §6), called once the client is authenticated
 * and registered for it.
 */
interface GrantInterface
{
    public function grantType(): GrantType;

    /**
     * @throws OAuth2Exception an error of RFC 6749 §5.2, answered as JSON
     */
    public function grant(Client $client, TokenRequest $request, RequestContext $context): IssuedTokens;
}
