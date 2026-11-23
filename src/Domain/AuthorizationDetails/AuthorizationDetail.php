<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\AuthorizationDetails;

use function array_map;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_float;
use function serialize;
use function sprintf;

/**
 * RFC 9396 §2
 */
final readonly class AuthorizationDetail
{
    public const string TYPE = 'type';

    /**
     * @param array<string, mixed> $members
     * @param array<string, string|int> $rendering the parameters of the message named after the type
     *
     * @throws InvalidArgumentException when the type is empty, or the members carry a "type" of their own
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
     * RFC 9396 §7, §9
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
     * Identical or not: RFC 9396 §7 leaves the comparison to the type, and identity is the one answer that never
     * grants more than was agreed to.
     */
    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->members === $other->members;
    }

    /**
     * The type and the members as one string, the same for two identical details and different for any other two
     * that JSON can write: a negative zero is written as zero, since -0.0 === 0.0.
     */
    public function identity(): string
    {
        return serialize([$this->type, self::zeroed($this->members)]);
    }

    /**
     * @param array<array-key, mixed> $members
     *
     * @return array<array-key, mixed>
     */
    private static function zeroed(array $members): array
    {
        return array_map(
            static fn (mixed $value): mixed => match (true) {
                is_float($value) => $value + 0.0,
                is_array($value) => self::zeroed($value),
                default => $value,
            },
            $members,
        );
    }
}
