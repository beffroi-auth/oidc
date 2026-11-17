<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Event\NamesItsAuthorInterface;

/**
 * An administrator read the applications a person agreed to through the administration API of their tenant: what each
 * one was granted, what it can still renew and what it asked that waits.
 *
 * A read that delivers a person to somebody else is an act of that person (decision 0022), and one done through the
 * administration API names the administrator beside them (decision 0038). The answer is written before the act is:
 * what the journal says is what was served, and a request the API refused writes nothing.
 */
final readonly class ConsentsReadByAnAdministrator implements ConcernsAClientInterface, ConcernsAPersonInterface, NamesItsAuthorInterface
{
    use ReadByAnAdministratorTrait;

    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
    public const string NAME = 'administration.consents_read';

    public function name(): string
    {
        return self::NAME;
    }
}
