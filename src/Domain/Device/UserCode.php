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
 * RFC 8628 §3.3, §6.1
 *
 * About 34 bits, enough only because the page limits the rate of wrong codes (RFC 8628 §5.1).
 */
final readonly class UserCode
{
    /**
     * RFC 8628 §6.1
     */
    public const string ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    public const int LENGTH = 8;

    /**
     * Characters per group of the formatted code: "BCDF-GHJK".
     */
    public const int GROUP = 4;

    public const string SEPARATOR = '-';

    private function __construct(
        public string $value,
    ) {
    }

    /**
     * @param string $characters the bare code, without separator
     *
     * @throws InvalidArgumentException
     */
    public static function of(#[SensitiveParameter] string $characters): self
    {
        if (! self::isWellFormed($characters)) {
            throw new InvalidArgumentException(sprintf('A user code is %d characters of "%s" (RFC 8628 section 6.1).', self::LENGTH, self::ALPHABET));
        }

        return new self($characters);
    }

    /**
     * RFC 8628 §6.1
     *
     * Only separators and spaces are dropped, so that anything else is refused rather than trimmed into a code.
     */
    public static function normalize(#[SensitiveParameter] string $typed): string
    {
        return strtoupper((string) preg_replace('/[\s' . self::SEPARATOR . ']+/', '', $typed));
    }

    /**
     * The code as the appliance shows it when what was typed is one, what was typed otherwise.
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

    public static function hashOf(#[SensitiveParameter] string $value): string
    {
        return DrawnSecret::digestOf($value);
    }

    public function hash(): string
    {
        return self::hashOf($this->value);
    }

    public function formatted(): string
    {
        return implode(self::SEPARATOR, str_split($this->value, self::GROUP));
    }
}
