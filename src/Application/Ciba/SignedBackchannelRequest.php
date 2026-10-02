<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use Beffroi\Oidc\Application\Authorization\ResolvedRequestObject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;

/**
 * What the backchannel authentication endpoint asks of what carried a request, once the request itself
 * has been read (FAPI-CIBA §5.2.2, CIBA Core §7.1.1).
 *
 * A client that registered "require_signed_request_object" is read from an object it signed here as at
 * the authorization endpoint: the registration says what a request of that client is made of, and it
 * does not stop saying it because this request arrived without a browser. That is what FAPI-CIBA §5.2.2
 * asks of every backchannel authentication request, and a profile is a registration here and never a
 * switch of the tenant (decision 0006).
 *
 * A signed one carries an "iat" and a "jti" beyond the four claims that bound what a signature proves
 * (RequestObjectValidator). §7.1.1 asks for both, and why it asks here and not there is the same reason
 * this endpoint exists: an object of the authorization endpoint carries a "nonce" and a "state" and is
 * bound to the one browser it was written for, where this one is bound to nothing but itself. So the
 * "jti" is remembered until the "exp" the object already has to carry, and one signed request is made
 * once: replaying it would draw a second identifier, keep a second record and ask a real person a
 * second time to approve one payment, which is what the provider already remembers a "jti" for twice
 * (RFC 7523 §3, RFC 9449 §11.1).
 *
 * The errors are the ones of §13, so what is refused here is "invalid_request".
 */
final readonly class SignedBackchannelRequest
{
    public function __construct(
        private RequestObjectReplayGuardInterface $replays,
    ) {
    }

    /**
     * @param ResolvedRequestObject|null $resolved what the request arrived in, null when it arrived as
     *                                             the form parameters of the body
     *
     * @throws InvalidRequestException
     */
    public function accept(?ResolvedRequestObject $resolved, Client $client): void
    {
        if ($resolved === null || ! $resolved->object->isSigned()) {
            if ($client->registration->requiresSignedRequestObject) {
                throw new InvalidRequestException('This client makes a backchannel authentication request with a request object it signed and no other way (OIDC Registration, require_signed_request_object; FAPI-CIBA section 5.2.2).');
            }

            return;
        }
        $jwt = $resolved->object->jwt;
        if ($jwt->time('iat') === null) {
            throw new InvalidRequestException('A signed backchannel authentication request carries an iat (CIBA Core section 7.1.1).');
        }
        $jti = $jwt->claim('jti');
        if ($jti === null) {
            throw new InvalidRequestException('A signed backchannel authentication request carries a jti (CIBA Core section 7.1.1).');
        }
        // the "exp" is the one RequestObjectValidator has already asked of the object and bounded, and
        // it is how long a "jti" has to be remembered for the object to be single use
        $expiresAt =
            $jwt->time('exp') ?? throw new LogicException('A signed request object reaches this rule validated, and an exp is one of the claims that were asked of it (RFC 9101 section 4).');
        if (! $this->replays->remember($client, $jti, $expiresAt)) {
            throw new InvalidRequestException('The jti of this backchannel authentication request has been used already (CIBA Core section 7.1.1).');
        }
    }
}
