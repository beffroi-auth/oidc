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
 * One grant type of the token endpoint (RFC 6749 §4.1.3, §6), called once the client is authenticated
 * and registered for it. What the client proved at that request comes with it, because that is what the
 * tokens of the response are bound to (RFC 8705 §3).
 *
 * One class per grant, wired into the provider: the grant names itself, and what the token endpoint
 * serves, what a client may register and what the discovery document announces are that one wired list.
 * A grant the provider gains is a class added to the wiring, never a case added to an enumeration, and
 * what it may issue is the capabilities it implements beside this one, never a rule written about its
 * name somewhere else.
 */
interface GrantInterface
{
    /**
     * The name of "grant_types_supported" (OIDC Discovery §3), which is also the name a client
     * registers and the "grant_type" of a token request.
     */
    public function grantType(): GrantTypeName;

    /**
     * @throws OAuth2Exception an error of RFC 6749 §5.2, answered as JSON
     * @throws ClientKeysUnavailableException when the keys of the client its ID token is encrypted to cannot be read, before anything the request presented is spent
     * @throws KmsUnavailableException when the KMS does not answer to open a key the response is signed with, which a grant somebody signed in for opens before anything the request presented is spent
     */
    public function grant(AuthenticatedClient $client, RequestParameters $request, RequestContext $context): IssuedTokens;
}
