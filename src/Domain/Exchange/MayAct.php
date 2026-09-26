<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Exchange;

use Heidi\Core\Domain\Identity\Subject;

/**
 * Who a token says may act for its subject (RFC 8693 §4.4, the "may_act" claim). It is a statement of the
 * provider about a token and not a wish of whoever presents one: a party the claim does not name is refused
 * the exchange whatever it authenticated as.
 *
 * It says who may act, not who may not: a token that carries none says nothing, and what decides then is
 * the registration of the party that asks (TokenExchange). A token that carries one narrows that to a
 * single party, and the outermost actor of the exchange is the one compared, the others having acted
 * already (§4.1).
 */
final readonly class MayAct
{
    public function __construct(
        public Subject $subject,
    ) {
    }

    /**
     * RFC 8693 §4.4: the party named here and nobody else. The chain is read at its outermost member,
     * which is the one about to act.
     */
    public function allows(Actor $actor): bool
    {
        return $this->subject->equals($actor->subject);
    }

    /**
     * RFC 8693 §4.4: the same shape as "act", of which this provider writes the "sub" and nothing else.
     *
     * @return array{sub: string}
     */
    public function toClaim(): array
    {
        return [
            'sub' => $this->subject->value,
        ];
    }

    public function equals(self $other): bool
    {
        return $this->subject->equals($other->subject);
    }
}
