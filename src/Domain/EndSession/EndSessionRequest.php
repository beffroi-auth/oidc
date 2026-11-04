<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\IdTokenHint;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * A logout request that passed validation (RP-Initiated Logout §2).
 */
final readonly class EndSessionRequest
{
    /**
     * @param list<string> $uiLocales most preferred first
     */
    public function __construct(
        public Tenant $tenant,
        public ?Client $client,
        public ?IdTokenHint $idTokenHint,
        public ?RedirectUri $postLogoutRedirectUri,
        public ?string $state = null,
        public ?string $logoutHint = null,
        public array $uiLocales = [],
        public bool $invalidIdTokenHint = false,
    ) {
        if ($idTokenHint !== null && $invalidIdTokenHint) {
            throw new InvalidArgumentException('A logout request carries a verified id_token_hint or an invalid one, not both.');
        }
        if ($client !== null && ! $client->belongsTo($tenant)) {
            throw new InvalidArgumentException('A logout request names a client of its own tenant.');
        }
        if ($idTokenHint !== null && ($client === null || ! $idTokenHint->isFor($client->registration->clientId))) {
            throw new InvalidArgumentException('The client of a logout request is one the id_token_hint was issued to.');
        }
        if ($postLogoutRedirectUri !== null && ($client === null || ! $client->registration->hasPostLogoutRedirectUri((string) $postLogoutRedirectUri))) {
            throw new InvalidArgumentException('A post_logout_redirect_uri is one the client registered (OIDC RP-Initiated Logout 1.0 §3).');
        }
        if ($state === '') {
            throw new InvalidArgumentException('The state of a logout request is either absent or non-empty.');
        }
    }

    public function redirect(): ?PostLogoutRedirect
    {
        if ($this->postLogoutRedirectUri === null) {
            return null;
        }

        return new PostLogoutRedirect($this->postLogoutRedirectUri, $this->state);
    }
}
