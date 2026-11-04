<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use function array_is_list;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Exception\InvalidArgumentException as CoreInvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function is_array;
use function is_int;
use function is_string;

/**
 * OIDC Core §2, RFC 8176 §2
 */
final readonly class AuthenticationSnapshot
{
    /**
     * @var non-empty-list<string>
     */
    public array $methods;

    /**
     * @param list<string> $methods at least one
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

    public static function ofSession(AuthenticationSession $session, AuthenticationContextClass $contextClass): self
    {
        return new self($session->authenticatedAt(), $session->methodReferences(), $contextClass->value);
    }

    /**
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
