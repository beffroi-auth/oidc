<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function array_is_list;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_int;
use function is_string;

/**
 * What the session had proven when the authorization was granted, frozen: the "auth_time", "amr" and
 * "acr" of every token descending from the grant (OIDC Core §2, RFC 8176 §2; architecture §4.6). A later
 * re-authentication or step-up moves the session, never the tokens already issued. One value, carried by
 * the code, the refresh token, the stored and the verified access token, written and read as claims here.
 */
final readonly class AuthenticationSnapshot
{
    /**
     * @var non-empty-list<string> the "amr" values
     */
    public array $methods;

    /**
     * @param list<string> $methods the "amr" values, at least one, each well formed (RFC 8176 §2)
     * @param string $contextClass the "acr" value, well formed (OIDC Core §2)
     */
    public function __construct(
        public DateTimeImmutable $authenticatedAt,
        array $methods,
        public string $contextClass,
    ) {
        if ($methods === []) {
            throw new InvalidArgumentException('An authentication records at least one method (RFC 8176).');
        }
        foreach ($methods as $method) {
            try {
                new AuthenticationMethod($method);
            } catch (CoreInvalidArgumentException $exception) {
                throw new InvalidArgumentException($exception->getMessage(), previous: $exception);
            }
        }
        if (! AuthenticationContextClass::isWellFormed($contextClass)) {
            throw new InvalidArgumentException('An authentication records a well-formed authentication context class reference (OIDC Core section 2).');
        }
        $this->methods = $methods;
    }

    /**
     * The session as it stands, with the class answered to the request (architecture §4.3: the first one
     * requested that the session satisfies, or the strongest one).
     */
    public static function ofSession(AuthenticationSession $session, AuthenticationContextClass $contextClass): self
    {
        return new self($session->authenticatedAt(), $session->methodReferences(), $contextClass->value);
    }

    /**
     * From the claims of a token this provider wrote, read strictly: anything else was not issued here.
     *
     * @param array<array-key, mixed> $claims
     *
     * @throws InvalidArgumentException
     */
    public static function fromClaims(array $claims): self
    {
        $authTime = $claims['auth_time'] ?? null;
        if (! is_int($authTime)) {
            throw new InvalidArgumentException('The auth_time claim is not a number of seconds.');
        }
        $amr = $claims['amr'] ?? null;
        if (! is_array($amr) || ! array_is_list($amr)) {
            throw new InvalidArgumentException('The amr claim is not a list.');
        }
        foreach ($amr as $method) {
            if (! is_string($method) || $method === '') {
                throw new InvalidArgumentException('The amr claim is not a list of strings.');
            }
        }
        $acr = $claims['acr'] ?? null;
        if (! is_string($acr) || $acr === '') {
            throw new InvalidArgumentException('The acr claim is not a string.');
        }

        return new self(new DateTimeImmutable('@' . $authTime), $amr, $acr);
    }

    /**
     * The three claims, in the order every token of the provider writes them.
     *
     * @return array{auth_time: int, acr: string, amr: non-empty-list<string>}
     */
    public function toClaims(): array
    {
        return [
            'auth_time' => $this->authenticatedAt->getTimestamp(),
            'acr' => $this->contextClass,
            'amr' => $this->methods,
        ];
    }
}
