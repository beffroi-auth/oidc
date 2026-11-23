<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use DateInterval;
use Beffroi\Oidc\Application\Authorization\ResolvedRequestObject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;

/**
 * FAPI-CIBA §5.2.2, CIBA Core §7.1.1
 */
final readonly class SignedBackchannelRequest
{
    public function __construct(
        private RequestObjectReplayGuardInterface $replays,
        private DateInterval $leeway,
    ) {
    }

    /**
     * @throws InvalidRequestException
     */
    public function accept(?ResolvedRequestObject $resolved, Client $client): void
    {
        if ($resolved === null || ! $resolved->object->isSigned()) {
            if ($client->registration->requiresSignedRequestObject) {
                throw new InvalidRequestException('This client makes a backchannel authentication request with a request object it signed and no other way (RFC 9101 section 10.5, require_signed_request_object; FAPI-CIBA section 5.2.2).');
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
        $expiresAt =
            $jwt->time('exp') ?? throw new LogicException('A signed request object reaches this rule validated, and an exp is one of the claims that were asked of it (RFC 9101 section 4).');
        // Until the last instant RequestObjectValidator accepts the object, or a replay inside the leeway is new again.
        if (! $this->replays->remember($client, $jti, $expiresAt->add($this->leeway))) {
            throw new InvalidRequestException('The jti of this backchannel authentication request has been used already (CIBA Core section 7.1.1).');
        }
    }
}
