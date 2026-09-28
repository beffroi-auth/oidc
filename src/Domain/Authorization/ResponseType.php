<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_map;

/**
 * What an authorization request may ask for (RFC 6749 §3.1.1, OIDC Core §3.1.2.1): a code, and nothing
 * else. Decision 0006 admits no implicit flow and no hybrid one, so the set is closed here and not by the
 * wiring, and it is read by the request that carries a response type, by the registration that names the
 * ones a client asks for (RFC 7591 §2 "response_types") and by the document that announces them.
 */
enum ResponseType: string
{
    /**
     * RFC 6749 §4.1: the authorization code flow, the only one this provider answers.
     */
    case Code = 'code';

    /**
     * @return non-empty-list<string>
     */
    public static function names(): array
    {
        return array_map(static fn (self $type): string => $type->value, self::cases());
    }
}
