<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function array_any;
use Heidi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What a client may do at the token exchange (RFC 8693 §2.1), as it registered it. A grant that turns a
 * token into another token is a grant that mints a subject, so what it may be asked is a closed list
 * written down in advance and never a parameter of the request: a client presenting something it did not
 * register for is refused whatever the thing says.
 *
 * Which types of token it may present is here; which resources it may ask the new token for is the
 * "resources" of the registration, as it is for every other grant (RFC 8707 §2.1), so that what a token of
 * this client may be addressed to is decided in one place. Whether it may act for a user at all is the
 * third: a gateway that carries a user's token is not the same party as a service that only ever exchanges
 * its own, and a deployment says which of the two it registered.
 */
final readonly class TokenExchange
{
    /**
     * @var non-empty-list<TokenTypeIdentifier>
     */
    public array $subjectTokenTypes;

    /**
     * @param list<TokenTypeIdentifier> $subjectTokenTypes the types of token this client may present as a "subject_token" or an "actor_token" (RFC 8693 §2.1), at least one
     * @param bool $mayActForAUser whether this client may present a token somebody signed in for; false for a client that only ever exchanges tokens of its own (RFC 6749 §4.4)
     *
     * @throws InvalidArgumentException when the client may present nothing, in which case it is registered for nothing
     */
    public function __construct(
        array $subjectTokenTypes,
        public bool $mayActForAUser,
    ) {
        if ($subjectTokenTypes === []) {
            throw new InvalidArgumentException('A client registered for the token exchange may present at least one type of token (RFC 8693 section 2.1).');
        }
        $this->subjectTokenTypes = $subjectTokenTypes;
    }

    /**
     * RFC 8693 §2.1: the "subject_token_type" and the "actor_token_type" of a request, compared byte for
     * byte as every other name a client registers.
     */
    public function allowsTokenType(TokenTypeIdentifier $type): bool
    {
        return array_any($this->subjectTokenTypes, static fn (TokenTypeIdentifier $registered): bool => $registered->equals($type));
    }
}
