<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Token;

use function array_keys;
use function array_values;
use function count;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Reads the "cnf" of RFC 7800 §3.1 back, whatever kept it: the claims of an "at+jwt" this provider
 * signed, the row of an opaque token, the members of an introspection response.
 *
 * This is the only place the member names are written down and the only place one is turned into the
 * class that speaks for it; a kind added is a class beside the two and a line here. A token is bound to
 * one thing: it was issued on a request that proved one possession, and a "cnf" naming two is not a
 * "cnf" this provider wrote.
 */
final readonly class Confirmations
{
    public const string CLAIM = 'cnf';

    /**
     * In the order the specifications came: RFC 8705 §3.1, then RFC 9449 §6.1.
     */
    public const array MEMBERS = [CertificateConfirmation::MEMBER, KeyConfirmation::MEMBER];

    /**
     * The claims of a token as they were written, read strictly: a "cnf" that is not an object, or that
     * names nothing this provider binds to, is a token this provider did not issue.
     *
     * @param array<array-key, mixed> $claims
     *
     * @throws InvalidArgumentException when the "cnf" names nothing this provider binds to
     */
    public static function fromClaims(array $claims): ?ConfirmationInterface
    {
        $confirmation = $claims[self::CLAIM] ?? null;
        if ($confirmation === null) {
            return null;
        }

        return self::fromMembers(is_array($confirmation) ? $confirmation : []);
    }

    /**
     * The members of a "cnf", however they were kept: read strictly, because a confirmation nobody can
     * read is a token bound to nothing.
     *
     * @param array<array-key, mixed> $members
     *
     * @throws InvalidArgumentException when no member is one this provider writes, when a member carries
     *                                  no thumbprint, or when several are there at once
     */
    public static function fromMembers(array $members): ConfirmationInterface
    {
        $read = [];
        foreach (self::MEMBERS as $member) {
            $value = $members[$member] ?? null;
            if ($value !== null) {
                $read[$member] = is_string($value)
                    ? self::named($member, $value)
                    : throw new InvalidArgumentException(sprintf('The "%s" member of a "cnf" carries a thumbprint (RFC 7800 section 3.1).', $member));
            }
        }
        if (count($read) > 1) {
            throw new InvalidArgumentException(sprintf('A token of this provider is bound to one thing, not to %s (RFC 7800 section 3.1).', implode(
                ' and ',
                array_keys($read),
            )));
        }

        return (
            array_values($read)[0] ?? throw new InvalidArgumentException(sprintf('The "cnf" of a token of this provider names one of %s (RFC 7800 section 3.1).', implode(
                ', ',
                self::MEMBERS,
            )))
        );
    }

    private static function named(string $member, string $value): ConfirmationInterface
    {
        return match ($member) {
            CertificateConfirmation::MEMBER => new CertificateConfirmation($value),
            default => new KeyConfirmation($value),
        };
    }
}
