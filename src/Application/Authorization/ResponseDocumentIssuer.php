<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use DateInterval;
use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Heidi\Oidc\Domain\Authorization\ResponseDocument;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Psr\Clock\ClockInterface;

/**
 * Mints the signed authorization response of one answer (JARM §2.1, architecture §4.3), signed by the
 * active key of the tenant in the algorithm the client registered in "authorization_signed_response_alg",
 * or in the one the provider signs with when it registered none, as an ID token is (OIDC Registration
 * §2). A refusal goes through here exactly as a code does (§2.4).
 *
 * No "typ" header: JARM fixes none, and a client that reads the document knows what it asked for.
 */
final readonly class ResponseDocumentIssuer
{
    /**
     * @param DateInterval $lifetime how long the document stays verifiable; short, a response being read
     *                               by the client as soon as the browser hands it over
     */
    public function __construct(
        private JwsSignerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT5M'),
    ) {
    }

    /**
     * @return string the compact JWS
     */
    public function issue(AuthorizationAnswer $answer): string
    {
        $client = $answer->client;
        $document = new ResponseDocument($client->tenant->issuer, $client->clientId, $answer->parameters, $this->clock->now()->add($this->lifetime));

        return $this->signer->sign(
            $client->tenant,
            $client->authorizationSignedResponseAlg ?? $this->algorithms->defaultAlgorithm(),
            JwtPayload::encode($document->claims()),
        );
    }
}
