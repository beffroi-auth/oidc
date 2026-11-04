<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use DateInterval;
use Beffroi\Oidc\Application\Client\ClientDocumentIssuer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Beffroi\Oidc\Domain\Authorization\ResponseDocument;
use Psr\Clock\ClockInterface;

/**
 * JARM §2.1
 */
final readonly class ResponseDocumentIssuer
{
    public function __construct(
        private ClientDocumentIssuer $documents,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT5M'),
    ) {
    }

    public function issue(AuthorizationAnswer $answer): string
    {
        $client = $answer->client;
        $document = new ResponseDocument(
            $client->tenant->issuer,
            $client->registration->clientId,
            $answer->parameters,
            $this->clock->now()->add($this->lifetime),
        );

        return $this->documents->issue($client, $this->documents->address($client, $client->registration->authorizationResponse), $document->claims());
    }
}
