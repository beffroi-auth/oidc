<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Exchange;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Domain\Token\TokenSignIn;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 8693 §2.1
 */
final readonly class PresentedToken
{
    /**
     * @param Subject $subject as whatever issued the token named them
     * @param Subject|null $person the subject of the person's account, as the token's type resolved it
     */
    public function __construct(
        public Subject $subject,
        public Client $client,
        public Scopes $scopes,
        public TokenAudience $audience,
        public Uuid $grantId,
        public ?TokenSignIn $signIn = null,
        public ?Actor $actor = null,
        public ?MayAct $mayAct = null,
        public ?Subject $person = null,
    ) {
    }

    public function isAboutAUser(): bool
    {
        return $this->signIn !== null || $this->person !== null;
    }
}
