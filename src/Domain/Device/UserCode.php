<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Device;

use function implode;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function preg_replace;
use SensitiveParameter;
use function sprintf;
use function str_split;
use function strtoupper;

/**
 * The code an appliance shows and the user types somewhere else (RFC 8628 §3.3). It is read out loud and
 * typed on a phone keyboard, so it is short and its alphabet has no character a reader takes for another:
 * the twenty consonants of RFC 8628 §6.1, without a vowel, so that eight of them spell no word anybody
 * has to read aloud to a stranger.
 *
 * Eight characters out of twenty are 20^8 combinations, a little over thirty-four bits, which is what
 * RFC 8628 §5.1 asks to be judged against the rate at which a code may be tried rather than on its own:
 * a code lives ten minutes by default and the page that takes one refuses a wrong one at a rate that
 * makes guessing pointless. What the provider keeps is the SHA-256 of the code and never the code, as for
 * every other value it hands out (DrawnSecret).
 *
 * Drawing one is UserCodeDrawer, which is given its randomness as a use case is given its clock. The
 * value kept here is the bare one; the separator is for the eye and is dropped from whatever the user
 * typed.
 */
final readonly class UserCode
{
    /**
     * RFC 8628 §6.1: twenty consonants, no vowel, nothing read for something else.
     */
    public const string ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public const int LENGTH = 8;

    /**
     * How the code is shown and how a form may come back with it: two groups of four ("BCDF-GHJK").
     */
    public const int GROUP = 4;

    public const string SEPARATOR = '-';

    private function __construct(
        public string $value,
    ) {
    }

    /**
     * @param string $characters the bare code, as UserCodeDrawer spells it
     *
     * @throws InvalidArgumentException when it is not a code of the shape this provider draws
     */
    public static function of(#[SensitiveParameter] string $characters): self
    {
        if (! self::isWellFormed($characters)) {
            throw new InvalidArgumentException(sprintf('A user code is %d characters of "%s" (RFC 8628 section 6.1).', self::LENGTH, self::ALPHABET));
        }

        return new self($characters);
    }

    /**
     * What the user typed, as it is compared: upper case, the separators and the spaces dropped
     * (RFC 8628 §6.1). Whether what is left is a code at all is isWellFormed()'s to say, so that a form
     * filled with anything is refused rather than trimmed into something.
     */
    public static function normalize(#[SensitiveParameter] string $typed): string
    {
        return strtoupper((string) preg_replace('/[\s' . self::SEPARATOR . ']+/', '', $typed));
    }

    /**
     * What a page shows back of what was typed: the code in the form the appliance shows it, separator
     * included, when what was typed is a code at all, and what was typed when it is not, so that a wrong
     * character can be corrected rather than hidden.
     *
     * It is the counterpart of normalize(): the bare value is the reading a lookup is made by, this one is
     * the reading a user recognises. A code shown without the grouping their device shows is a code they
     * have to re-read character by character before allowing anything, which is the recognition BCP 10027
     * §2 is about.
     */
    public static function shown(#[SensitiveParameter] string $typed): string
    {
        $value = self::normalize($typed);

        return self::isWellFormed($value) ? self::of($value)->formatted() : $value;
    }

    public static function isWellFormed(#[SensitiveParameter] string $value): bool
    {
        return preg_match(sprintf('/^[%s]{%d}$/D', self::ALPHABET, self::LENGTH), $value) === 1;
    }

    /**
     * What a store keeps of a code, and what a lookup is made by.
     */
    public static function hashOf(#[SensitiveParameter] string $value): string
    {
        return DrawnSecret::digestOf($value);
    }

    public function hash(): string
    {
        return self::hashOf($this->value);
    }

    /**
     * The code as the appliance shows it and as the page shows it back.
     */
    public function formatted(): string
    {
        return implode(self::SEPARATOR, str_split($this->value, self::GROUP));
    }
}
