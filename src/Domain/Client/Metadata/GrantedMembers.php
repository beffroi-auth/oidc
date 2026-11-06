<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

use function array_keys;
use function array_pop;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use function implode;
use function in_array;
use function sprintf;

/**
 * RFC 7591 §1.2
 *
 * The members of the deployment an initial access token gives the clients it registers, which no client sends.
 */
final readonly class GrantedMembers implements ClientMetadataSourceInterface
{
    /**
     * Neither the consent nor PKCE: a token gives, it never takes a requirement away (decision 0043).
     *
     * @var list<string>
     */
    public const array NAMES = [
        'resources',
        'access_token_format',
        'require_sender_constrained_tokens',
        'token_exchange',
        'may_act',
    ];

    private const string SOURCE = 'the initial access token the tenant issued';

    /**
     * @param array<string, mixed> $members
     *
     * @throws InvalidClientMetadataException
     */
    public function __construct(
        private array $members,
    ) {
        foreach (array_keys($members) as $member) {
            self::assertGiven((string) $member);
        }
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidClientMetadataException
     */
    public static function fromDocument(array $document): self
    {
        $members = [];
        foreach ($document as $member => $value) {
            $members[(string) $member] = $value;
        }

        return new self($members);
    }

    public function source(): string
    {
        return self::SOURCE;
    }

    public function members(): array
    {
        return $this->members;
    }

    /**
     * @return array<string, mixed>
     */
    public function toDocument(): array
    {
        return $this->members;
    }

    /**
     * @throws InvalidClientMetadataException
     */
    private static function assertGiven(string $member): void
    {
        if (in_array($member, self::NAMES, true)) {
            return;
        }
        $given = self::NAMES;
        $last = array_pop($given);

        throw new InvalidClientMetadataException(
            $member,
            self::SOURCE,
            sprintf(
                'The member "%s" is not one an initial access token gives: a token gives the clients it registers %s and %s, and nothing else (decision 0043).',
                $member,
                implode(', ', $given),
                $last,
            ),
        );
    }
}
