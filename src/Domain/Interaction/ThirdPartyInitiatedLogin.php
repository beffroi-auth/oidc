<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Domain\Client\InitiateLoginUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;

/**
 * OIDC Core §4
 *
 * Everything it carries comes from the client's registration or from this provider, never from the request:
 * otherwise this would be an open redirector.
 */
final readonly class ThirdPartyInitiatedLogin
{
    /**
     * @var non-empty-array<non-empty-string, string>
     */
    public array $parameters;

    /**
     * @param Subject|null $loginHint the subject as this client sees it (OIDC Core §8)
     */
    public function __construct(
        public InitiateLoginUri $initiateLoginUri,
        public Issuer $issuer,
        public ?Subject $loginHint = null,
        public ?RedirectUri $targetLinkUri = null,
    ) {
        $parameters = [
            'iss' => $issuer->value,
        ];
        if ($loginHint !== null) {
            $parameters['login_hint'] = $loginHint->value;
        }
        if ($targetLinkUri !== null) {
            $parameters['target_link_uri'] = $targetLinkUri->value;
        }
        $this->parameters = $parameters;
    }

    public function location(): string
    {
        return $this->initiateLoginUri->withParameters($this->parameters);
    }
}
