<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Request;

use function array_is_list;
use function explode;
use Beffroi\Oidc\Exception\InvalidRequestException;
use function in_array;
use function is_array;
use function is_string;
use function preg_match;
use function sprintf;

/**
 * RFC 6749 §3.1
 *
 * Nothing is cast, and every pattern ends with the D modifier so that "$" never matches before a final newline.
 */
final readonly class RequestParameters
{
    /**
     * RFC 6749 appendix A.5
     */
    public const string STATE_PATTERN = '/^[\x20-\x7E]+$/D';

    public const string TEXT_PATTERN = '/^[^\p{Cc}]+$/Du';

    /**
     * RFC 5646 §2.1, loosely
     */
    public const string LANGUAGE_TAG_PATTERN = '/^[A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*$/D';

    /**
     * RFC 7515 §7.1
     *
     * The third segment is never empty: OIDC Core §2 forbids "none".
     */
    public const string COMPACT_JWS_PATTERN = '/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D';

    /**
     * OIDC Core §2
     */
    public const string ACR_VALUE_PATTERN = '/^[\x21-\x7E]+$/D';

    /**
     * @param array<string, mixed> $parameters
     */
    private function __construct(
        private array $parameters,
        private bool $redirectable,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public static function of(array $parameters): self
    {
        return new self($parameters, false);
    }

    public function withRedirectableFailures(): self
    {
        return new self($this->parameters, true);
    }

    public function isPresent(string $name): bool
    {
        return ($this->parameters[$name] ?? '') !== '';
    }

    /**
     * RFC 6749 §3.1
     *
     * @throws InvalidRequestException when the parameter is not a single string
     */
    public function optional(string $name): ?string
    {
        $value = $this->parameters[$name] ?? '';
        if ($value === '') {
            return null;
        }
        if (! is_string($value)) {
            throw new InvalidRequestException(sprintf('The %s parameter must be a single string.', $name), $this->redirectable);
        }

        return $value;
    }

    /**
     * @throws InvalidRequestException when the parameter is missing, empty, or not a single string
     */
    public function required(string $name): string
    {
        return $this->optional($name) ?? throw new InvalidRequestException(sprintf('The %s parameter is missing.', $name), $this->redirectable);
    }

    /**
     * RFC 6749 §4.1.1
     *
     * Never redirectable: where an answer may go is read off the client, which is not known yet.
     *
     * @throws InvalidRequestException when the parameter is missing, or is not a single string
     */
    public function clientId(): string
    {
        return $this->optional('client_id') ?? throw new InvalidRequestException('The client_id parameter is missing.');
    }

    public function state(): ?string
    {
        $state = $this->optional('state');
        if ($state !== null && preg_match(self::STATE_PATTERN, $state) !== 1) {
            throw new InvalidRequestException('The state parameter must be printable ASCII text (RFC 6749 appendix A.5).', $this->redirectable);
        }

        return $state;
    }

    public function text(string $name): ?string
    {
        $value = $this->optional($name);
        if ($value !== null && preg_match(self::TEXT_PATTERN, $value) !== 1) {
            throw new InvalidRequestException(sprintf('The %s parameter must be text without control characters.', $name), $this->redirectable);
        }

        return $value;
    }

    public function compactJws(string $name): ?string
    {
        $value = $this->optional($name);
        if ($value !== null && preg_match(self::COMPACT_JWS_PATTERN, $value) !== 1) {
            throw new InvalidRequestException(sprintf('The %s parameter is not a signed compact JWT.', $name), $this->redirectable);
        }

        return $value;
    }

    /**
     * OIDC Core §3.1.2.1
     *
     * @return list<string> most preferred first
     */
    public function uiLocales(): array
    {
        return $this->list(
            'ui_locales',
            self::LANGUAGE_TAG_PATTERN,
            'The ui_locales parameter must be a space-separated list of language tags.',
        );
    }

    /**
     * OIDC Core §3.1.2.1, CIBA Core §7.1
     *
     * @return list<string> in the client's order of preference
     */
    public function acrValues(): array
    {
        return $this->list(
            'acr_values',
            self::ACR_VALUE_PATTERN,
            'The acr_values parameter must be a space-separated list of printable ASCII values.',
        );
    }

    /**
     * RFC 8707 §2
     *
     * @throws InvalidRequestException when the parameter is neither a string nor a list of them
     *
     * @return list<string>
     */
    public function repeated(string $name): array
    {
        $value = $this->parameters[$name] ?? '';
        if ($value === '' || $value === []) {
            return [];
        }
        if (is_string($value)) {
            return [$value];
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidRequestException(sprintf('The %s parameter must be a string or a list of strings.', $name), $this->redirectable);
        }
        $values = [];
        foreach ($value as $item) {
            if (! is_string($item) || $item === '') {
                throw new InvalidRequestException(sprintf('The %s parameter must be a string or a list of strings.', $name), $this->redirectable);
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
     * @return list<string>
     */
    public function list(string $name, string $pattern, string $description): array
    {
        $value = $this->optional($name);
        if ($value === null) {
            return [];
        }
        $items = [];
        foreach (explode(' ', $value) as $item) {
            if (preg_match($pattern, $item) !== 1) {
                throw new InvalidRequestException($description, $this->redirectable);
            }
            if (! in_array($item, $items, true)) {
                $items[] = $item;
            }
        }

        return $items;
    }
}
