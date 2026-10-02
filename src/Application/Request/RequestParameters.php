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
 * The raw parameters of a request, read the one way every endpoint of this provider reads them
 * (RFC 6749 §3.1): a single string, a repeated or nested one refused, an empty one omitted, an unknown
 * one ignored. Nothing is cast; every pattern ends with the D modifier. A parameter a specification
 * allows to repeat is the one exception, and it is read as the list it is.
 *
 * Whether a failure may be redirected back to the client is a property of the stage that reads, not of
 * the parameter: the first stage of an authorization request knows no redirect URI yet and the token
 * endpoint answers in JSON, so what they read refuses without a redirect; the second stage of an
 * authorization request answers to the client, so what it reads refuses with one. The caller says which
 * it is once, when it takes the parameters up, and every rule below follows.
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
     * OIDC Core §2 "acr": printable ASCII without space.
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
     * The parameters as an endpoint received them, whose failures are refused on the spot: no redirect
     * URI is known yet, or the endpoint answers in JSON and never redirects at all.
     *
     * @param array<string, mixed> $parameters
     */
    public static function of(array $parameters): self
    {
        return new self($parameters, false);
    }

    /**
     * The same parameters, read by a stage whose failures go back to the client with "state" and "iss"
     * (RFC 6749 §4.1.2.1, RFC 9207 §2).
     */
    public function withRedirectableFailures(): self
    {
        return new self($this->parameters, true);
    }

    public function isPresent(string $name): bool
    {
        return ($this->parameters[$name] ?? '') !== '';
    }

    /**
     * RFC 6749 §3.1: empty is omitted, repeated or nested is refused.
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
     * RFC 6749 §4.1.1: the client names itself in every request that reaches an endpoint reading this,
     * and one that names nobody names nothing to look up. Never redirectable: where an answer may go is
     * read off the client, so it is not known yet.
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
     * OIDC Core §3.1.2.1 "ui_locales": most preferred first.
     *
     * @return list<string>
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
     * OIDC Core §3.1.2.1, CIBA Core §7.1 "acr_values": the classes the client would like the
     * authentication to reach, in its order of preference. One reading for the two doors, the one a
     * browser reaches and the one a client with no browser at all does.
     *
     * @return list<string>
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
     * A parameter a specification allows to be sent several times (RFC 8707 §2), which RFC 6749 §3.1
     * forbids for every other one: what arrives is a single string, a list of them, or nothing. Values
     * are kept in the order they came, without repeats, and nothing is cast.
     *
     * @throws InvalidRequestException when the parameter is neither a string nor a list of them
     *
     * @return list<string> empty when the request carries none
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
