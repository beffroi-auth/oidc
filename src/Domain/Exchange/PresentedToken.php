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
 * What a token presented at an exchange says, whatever type it was presented as (RFC 8693 §2.1): who it is
 * about, who holds it, what it is good for and who may act for its subject.
 *
 * It is what the exchange narrows and never widens (§2.1), and it is the same shape whichever type read it:
 * a type the provider gains reads its own tokens into this, and the grant reads nothing of the type it was
 * handed.
 */
final readonly class PresentedToken
{
    /**
     * @param Subject $subject who the token is about, as whatever issued it named them (RFC 8693 §2.2.1)
     * @param Client $client the client the token was issued to, which the exchange names as the actor it acts through
     * @param Scopes $scopes what the token is good for, which the new one is a subset of (RFC 8693 §2.1)
     * @param TokenAudience $audience who the token is addressed to (RFC 8707 §2), which the new one is addressed inside of
     * @param Uuid $grantId what the token descends from, which the new one descends from too: taking that grant back takes both
     * @param TokenSignIn|null $signIn the sign-in the token descends from, null when nobody signed in for it (RFC 6749 §4.4)
     * @param Actor|null $actor who already acts for the subject (RFC 8693 §4.1), null when nobody does; a further exchange adds its actor around this one
     * @param MayAct|null $mayAct who may act for the subject (RFC 8693 §4.4), null when nothing says
     * @param Subject|null $person the person the token was issued in the name of, as the type that read it resolved its "sub" (OIDC Core §8.1, issue #588); null when the token names nobody
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

    /**
     * Whether somebody signed in for the token (RFC 6749 §4.4): what a client registered to act for a user
     * is checked against, and what says whether the new token carries a "sid" of its own.
     */
    public function isAboutAUser(): bool
    {
        return $this->signIn !== null;
    }
}
