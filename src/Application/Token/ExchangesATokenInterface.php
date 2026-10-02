<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Token;

/**
 * A grant that takes a token as its input and gives a token back (RFC 8693 §2.1): the client presents
 * something that names somebody, and receives a token that names the same somebody for another resource.
 *
 * A grant declares this instead of anything reading its name: what a registration of such a grant must carry,
 * the closed list of what the client may present, is decided where a registration meets the wiring, from
 * this.
 */
interface ExchangesATokenInterface extends GrantInterface
{
}
