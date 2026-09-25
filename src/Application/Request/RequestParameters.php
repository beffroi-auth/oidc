<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Request;

use function array_is_list;
use function explode;
use Heidi\Oidc\Exception\InvalidRequestException;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * How the browser-facing endpoints read their parameters (RFC 6749 §3.1): a single string, a repeated
 * or nested one refused, an empty one omitted, an unknown one ignored. Nothing is cast; every pattern
 * ends with the D modifier. Whether a failure is redirectable is the caller's to say.
 */
final readonly class RequestParameters
{
    /**
     * RFC 6749 appendix A.5: state = 1*VSCHAR (%x20-7E).
     */
    public const string STATE_PATTERN = '/^[\x20-\x7E]+$/D';

    /**
     * Free text (nonce, login_hint, logout_hint): valid UTF-8 without control characters.
     */
    public const string TEXT_PATTERN = '/^[^\p{Cc}]+$/Du';

    /**
     * RFC 5646 §2.1, loosely; whether the tag is supported is the integration's concern.
     */
    public const string LANGUAGE_TAG_PATTERN = '/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/D';

    /**
     * RFC 7515 §7.1, the third segment never empty (OIDC Core §2 forbids "none").
     */
    public const string COMPACT_JWS_PATTERN = '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D';

    /**
     * RFC 6749 §3.1: empty is omitted, repeated or nested is refused.
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
     * RFC 6749 §4.1.1: the client names itself in every request that reaches these endpoints, and one
     * that names nobody names nothing to look up. Never redirectable: where an answer may go is read
     * off the client, so it is not known yet.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws InvalidRequestException when the parameter is missing, or is not a single string
     */
    public static function clientId(array $parameters): string
    {
        return self::single($parameters, 'client_id', false) ?? throw new InvalidRequestException('The client_id parameter is missing.');
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
     * OIDC Core §3.1.2.1 "ui_locales": most preferred first.
     *
     * @param array<string, mixed> $parameters
     *
     * @return list<string>
     */
    public static function uiLocales(array $parameters, bool $redirectable): array
    {
        return self::list(
            $parameters,
            'ui_locales',
            self::LANGUAGE_TAG_PATTERN,
            'The ui_locales parameter must be a space-separated list of language tags.',
            $redirectable,
        );
    }

    /**
     * A parameter a specification allows to be sent several times (RFC 8707 §2), which RFC 6749 §3.1
     * forbids for every other one: what arrives is a single string, a list of them, or nothing. Values
     * are kept in the order they came, without repeats, and nothing is cast.
     *
     * @param array<string, mixed> $parameters
     *
     * @return list<string> empty when the request carries none
     */
    public static function repeated(array $parameters, string $name, bool $redirectable): array
    {
        $value = $parameters[$name] ?? '';
        if ($value === '' || $value === []) {
            return [];
        }
        if (is_string($value)) {
            return [$value];
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidRequestException(sprintf('The %s parameter must be a string or a list of strings.', $name), $redirectable);
        }
        $values = [];
        foreach ($value as $item) {
            if (! is_string($item) || $item === '') {
                throw new InvalidRequestException(sprintf('The %s parameter must be a string or a list of strings.', $name), $redirectable);
            }
            if (! in_array($item, $values, true)) {
                $values[] = $item;
            }
        }

        return $values;
    }

    /**
     * Space-separated, every item matching the pattern, without repeats.
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
