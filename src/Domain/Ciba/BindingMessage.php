<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function mb_strlen;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * CIBA Core §7.1, §13, BCP 10027 §5.2
 *
 * The alphabet is restricted so that the message can neither pass for the provider's own words nor turn its line
 * around; what falls outside is refused, never trimmed.
 */
final readonly class BindingMessage implements Stringable
{
    /**
     * Readable at a glance on a phone or a payment terminal; CIBA Core §7.1 names no number.
     */
    public const int MAX_LENGTH = 64;

    private const string PATTERN = '/^[\p{L}\p{M}\p{N}\p{Zs}\p{Sc}.,:;!?()\[\]@#%+*\/=_-]+$/Du';

    /**
     * @throws InvalidArgumentException
     */
    public function __construct(
        public string $value,
    ) {
        if (mb_strlen($value) > self::MAX_LENGTH) {
            throw new InvalidArgumentException(sprintf(
                'A binding message is at most %d characters, being read on the device where the request is approved (CIBA Core section 7.1).',
                self::MAX_LENGTH,
            ));
        }
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidArgumentException('A binding message is plain text: letters, digits, spaces and ordinary punctuation, nothing that formats the line it is shown on (CIBA Core section 7.1).');
        }
    }

    public function __toString(): string
    {
        return $this->value;
    }
}
