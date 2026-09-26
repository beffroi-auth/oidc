<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Exchange;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_string;

/**
 * Who acts for the subject of a token (RFC 8693 §4.1, the "act" claim): the party the token was handed to,
 * and, when it in turn received the token from another, that other one nested inside it.
 *
 * The nesting is the history and the outermost member is the present: "the most recent actor is the
 * outermost" (§4.1). A chain is therefore never flattened and never reordered, and a second exchange adds
 * an actor around the chain it found rather than replacing it, which is what a resource server reads to
 * know who is standing in front of it and through whom.
 *
 * A token that carries no "act" at all names nobody acting for its subject, which is what impersonation is
 * (§1.3): the new token is the subject, and nothing says that somebody else is holding it.
 */
final readonly class Actor
{
    /**
     * @param Subject $subject who is acting, as the "sub" of the "act" claim names them (RFC 8693 §4.1)
     * @param self|null $actor the actor this one received the token from, null when it received it from the subject itself
     */
    public function __construct(
        public Subject $subject,
        public ?self $actor = null,
    ) {
    }

    /**
     * The same chain with this actor added on the outside (RFC 8693 §4.1): what a second exchange writes,
     * the one it found becoming the one it acts through.
     */
    public function actingThrough(?self $previous): self
    {
        return new self($this->subject, $previous);
    }

    /**
     * RFC 8693 §4.1: "sub" names the actor, "act" the one it acts through, and nothing else is written.
     *
     * @return array{sub: string, act?: array<string, mixed>}
     */
    public function toClaim(): array
    {
        $claim = [
            'sub' => $this->subject->value,
        ];
        if ($this->actor !== null) {
            $claim['act'] = $this->actor->toClaim();
        }

        return $claim;
    }

    /**
     * RFC 8693 §4.1: an object with a "sub", and an "act" of the same shape inside it when there is one.
     * Nothing else of the object is read: a member this provider does not write is not one it believes.
     *
     * @throws InvalidArgumentException when the claim is not what this provider writes
     */
    public static function fromClaim(mixed $act): self
    {
        if (! is_array($act)) {
            throw new InvalidArgumentException('An "act" claim is a JSON object (RFC 8693 section 4.1).');
        }
        $subject = $act['sub'] ?? null;
        if (! is_string($subject)) {
            throw new InvalidArgumentException('An "act" claim names the actor in its "sub" (RFC 8693 section 4.1).');
        }
        try {
            return new self(new Subject($subject), isset($act['act']) ? self::fromClaim($act['act']) : null);
        } catch (CoreInvalidArgumentException $exception) {
            throw new InvalidArgumentException('The "sub" of an "act" claim is a subject (OIDC Core section 2).', previous: $exception);
        }
    }

    public function equals(self $other): bool
    {
        return (
            $this->subject->equals($other->subject)
            && ($this->actor === null ? $other->actor === null : $other->actor !== null && $this->actor->equals($other->actor))
        );
    }
}
