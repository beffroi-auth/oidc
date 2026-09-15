<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Request;

use function explode;
use Heidi\Oidc\Exception\InvalidRequestException;
use function in_array;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * How the browser-facing endpoints read their parameters (RFC 6749 §3.1, OIDC RP-Initiated Logout 1.0
 * §2): every parameter is a single string, a repeated or nested one is refused, one without a value is
 * treated as omitted, an unknown one is ignored. Nothing is cast, nothing is defaulted on the client's
 * behalf, and every pattern is anchored at the very end of the value (the D modifier), because "$"
 * alone lets a trailing newline through. Whether a failure may be sent back to the client is the caller's to say: only the
 * authorization endpoint ever redirects one, and only once it holds a validated redirect URI.
 */
final readonly class RequestParameters
{
    /**
     * RFC 6749 appendix A.5: state = 1*VSCHAR (%x20-7E).
     */
    public const string STATE_PATTERN = '/^[\x20-\x7E]+$/D';

    /**
     * A free-text parameter (nonce, login_hint, logout_hint): valid UTF-8 without control characters. A
     * nonce comes back in a JSON claim, a hint reaches a form; neither has a use for a control character.
     */
    public const string TEXT_PATTERN = '/^[^\p{Cc}]+$/Du';

    /**
     * RFC 5646 §2.1, loosely: a language tag is subtags of one to eight letters or digits joined by
     * hyphens, the first one letters only. Whether the tag is supported is the integration's concern.
     */
    public const string LANGUAGE_TAG_PATTERN = '/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/D';

    /**
     * RFC 7515 §7.1: a compact JWS is three base64url segments; an ID token issued here is always
     * signed, so the third segment is never empty (OIDC Core §2 forbids "none" for the code flow).
     */
    public const string COMPACT_JWS_PATTERN = '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D';

    /**
     * RFC 6749 §3.1: a parameter without a value is treated as omitted, a parameter must not be
     * included more than once. A value that is not a string (an array, from a repeated or nested
     * parameter) is refused rather than reduced to one.
     *
     * @param array<string, mixed> $parameters
     */
    public static function single(array $parameters, string $name, bool $redirectable): ?string
    {
        $value = $parameters[$name] ?? '';
        if ($value === '') {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidRequestException(sprintf('The %s parameter must be a single string.', $name), $redirectable);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function isPresent(array $parameters, string $name): bool
    {
        return ($parameters[$name] ?? '') !== '';
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function state(array $parameters, bool $redirectable): ?string
    {
        $state = self::single($parameters, 'state', $redirectable);
        if ($state !== null && preg_match(self::STATE_PATTERN, $state) !== 1) {
            throw new InvalidRequestException('The state parameter must be printable ASCII text (RFC 6749 appendix A.5).', $redirectable);
        }

        return $state;
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function text(array $parameters, string $name, bool $redirectable): ?string
    {
        $value = self::single($parameters, $name, $redirectable);
        if ($value !== null && preg_match(self::TEXT_PATTERN, $value) !== 1) {
            throw new InvalidRequestException(sprintf('The %s parameter must be text without control characters.', $name), $redirectable);
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function compactJws(array $parameters, string $name, bool $redirectable): ?string
    {
        $value = self::single($parameters, $name, $redirectable);
        if ($value !== null && preg_match(self::COMPACT_JWS_PATTERN, $value) !== 1) {
            throw new InvalidRequestException(sprintf('The %s parameter is not a signed compact JWT.', $name), $redirectable);
        }

        return $value;
    }

    /**
     * OIDC Core §3.1.2.1 and RP-Initiated Logout §2 "ui_locales": language tags, most preferred first.
     *
     * @param array<string, mixed> $parameters
     *
     * @return list<string>
     */
    public static function uiLocales(array $parameters, bool $redirectable): array
    {
        return self::list($parameters, 'ui_locales', self::LANGUAGE_TAG_PATTERN, 'The ui_locales parameter must be a space-separated list of language tags.', $redirectable);
    }

    /**
     * A space-separated list whose every item matches the pattern, in the order given, without repeats.
     *
     * @param array<string, mixed> $parameters
     *
     * @return list<string>
     */
    public static function list(array $parameters, string $name, string $pattern, string $description, bool $redirectable): array
    {
        $value = self::single($parameters, $name, $redirectable);
        if ($value === null) {
            return [];
        }
        $items = [];
        foreach (explode(' ', $value) as $item) {
            if (preg_match($pattern, $item) !== 1) {
                throw new InvalidRequestException($description, $redirectable);
            }
            if (! in_array($item, $items, true)) {
                $items[] = $item;
            }
        }

        return $items;
    }
}
