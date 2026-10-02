<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Ciba;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use function mb_strlen;
use function preg_match;
use function sprintf;
use Stringable;

/**
 * The message the client sends so that its user can tell, on the device where they approve, that they are
 * approving what they started somewhere else (CIBA Core §7.1, §13): "a human-readable identifier or
 * message intended to be displayed on both devices", "relatively short and use a limited set of plain
 * text characters".
 *
 * It is the one string of this flow a third party writes and a user reads, which is what BCP 10027 §5.2
 * is about: what is shown beside the name of a client must not be able to pass for the provider's own
 * words, nor to turn the line it is written on around. So the alphabet is letters, marks, digits,
 * spaces, currency signs and a short list of punctuation, and nothing else: no control character, no
 * direction override, none of the characters that carry meaning in the page it is rendered in. What is
 * not that is refused with "invalid_binding_message" (§13) rather than trimmed into something the client
 * did not send.
 */
final readonly class BindingMessage implements Stringable
{
    /**
     * Short enough to be read at a glance on a phone and on a payment terminal, which is what §7.1 asks
     * for without naming a number.
     */
    public const int MAX_LENGTH = 64;

    private const string PATTERN = '/^[\p{L}\p{M}\p{N}\p{Zs}\p{Sc}.,:;!?()\[\]@#%+*\/=_-]+$/Du';

    /**
     * @throws InvalidArgumentException when the message is not one a user can be shown as it is; the
     *                                  endpoint that read it answers "invalid_binding_message" (§13)
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
