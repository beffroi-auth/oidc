<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use function array_any;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * What a client is registered to exchange (RFC 8693 §2.1).
 */
final readonly class TokenExchange
{
    /**
     * @var non-empty-list<TokenTypeIdentifier>
     */
    public array $subjectTokenTypes;

    /**
     * @param list<TokenTypeIdentifier> $subjectTokenTypes presentable as a subject or an actor token, at least one
     *
     * @throws InvalidArgumentException
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
     * RFC 8693 §2.1
     */
    public function allowsTokenType(TokenTypeIdentifier $type): bool
    {
        return array_any($this->subjectTokenTypes, static fn (TokenTypeIdentifier $registered): bool => $registered->equals($type));
    }
}
