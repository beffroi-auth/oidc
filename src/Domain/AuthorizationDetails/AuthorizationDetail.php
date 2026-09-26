<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\AuthorizationDetails;

use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;

/**
 * One object of an "authorization_details" array (RFC 9396 §2), as the type that answers for its "type"
 * kept it: what that type validated, ready to be written into a token (§7) and rendered by an
 * introspection (§9), and what a page says of it in the words of that type.
 *
 * A scope says what kind of thing a client may do; a detail says what it may do, to what, and how much,
 * which is why it is the one thing an authorization carries that a user has to be able to read before
 * agreeing to it. Nothing here knows what any of it means: the members are whatever the type of this
 * detail accepted, and the type is the only place that decides.
 *
 * The members are the ones the type built, in the order it built them, so two details of one type that
 * ask for the same thing are the same detail whatever order the request wrote them in. They are named,
 * which is what the reader guarantees before a type ever sees them. "type" is not among them: it is
 * carried on its own and written back first.
 */
final readonly class AuthorizationDetail
{
    /**
     * RFC 9396 §2: the one member every object of the array carries.
     */
    public const string TYPE = 'type';

    /**
     * @param string $type the value of the "type" member, which names the class that read this detail
     * @param array<string, mixed> $members the other members, as that class validated and ordered them
     * @param array<string, string|int> $rendering what a page says of this detail: the parameters of the
     *                                             message named after the type, in the reader's language
     *
     * @throws InvalidArgumentException when the type is empty, or when the members carry a "type" of their own
     */
    public function __construct(
        public string $type,
        public array $members = [],
        public array $rendering = [],
    ) {
        if ($type === '') {
            throw new InvalidArgumentException('An authorization detail names its type (RFC 9396 section 2).');
        }
        if (isset($members[self::TYPE])) {
            throw new InvalidArgumentException(sprintf(
                'The members of an authorization detail of the type "%s" carry no "type" of their own: the detail carries it.',
                $type,
            ));
        }
    }

    /**
     * RFC 9396 §7, §9: the object as an access token carries it and as an introspection renders it,
     * "type" first, because that is the member the resource server reads before any other.
     *
     * @return non-empty-array<string, mixed>
     */
    public function toClaim(): array
    {
        return [
            self::TYPE => $this->type,
            ...$this->members,
        ];
    }

    /**
     * Whether the two ask for the same thing: the same type, carrying the same members. RFC 9396 leaves
     * the comparison of two details to whoever defines their type (§7), and what this provider makes of
     * that is the one answer that can never grant more than was agreed to: a detail is covered by a
     * detail that is identical to it and by no other, so a request that changed anything at all asks
     * again rather than being served on a consent that was given for something else.
     */
    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->members === $other->members;
    }
}
