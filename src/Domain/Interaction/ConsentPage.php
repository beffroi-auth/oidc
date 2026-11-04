<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientUri;

/**
 * What the consent page shows of the client asking; the browser loads its logo, the provider never fetches it.
 */
final readonly class ConsentPage
{
    /**
     * @var array<non-empty-string, ClientUri> by registering member (OIDC Registration §2), in display order
     */
    public array $links;

    /**
     * @var list<string> origins and never URLs (RFC 6454 §3.2, CSP Level 3 §2.3)
     */
    public array $imageOrigins;

    public function __construct(
        public ClientPresentation $presentation,
    ) {
        $links = [];
        foreach ([
            'policy_uri' => $presentation->policyUri,
            'tos_uri' => $presentation->tosUri,
            'client_uri' => $presentation->uri,
        ] as $member => $uri) {
            if ($uri !== null) {
                $links[$member] = $uri;
            }
        }
        $this->links = $links;

        $this->imageOrigins = $presentation->logoUri === null ? [] : [$presentation->logoUri->origin];
    }
}
