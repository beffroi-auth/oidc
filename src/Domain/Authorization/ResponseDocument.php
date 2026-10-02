<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The claims of a signed authorization response (JARM §2.1): the parameters the answer would have
 * carried, each one a claim of its own, plus the three the module adds, "iss", "aud" naming the client
 * the document is for and "exp" bounding how long it is worth anything. A refusal is the same document
 * with "error" among its parameters (§2.4): a client that asked for a signed answer never reads an
 * unsigned one.
 */
final readonly class ResponseDocument
{
    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters the response as the protocol names it, "state" and "iss" included
     */
    public function __construct(
        public Issuer $issuer,
        public string $audience,
        array $parameters,
        public DateTimeImmutable $expiresAt,
    ) {
        if ($parameters === []) {
            throw new InvalidArgumentException('A signed authorization response carries at least one parameter (JARM section 2.1).');
        }
        $this->parameters = $parameters;
    }

    /**
     * The parameters first, each under its own name, then the three claims of §2.1; "iss" is already
     * among the parameters (RFC 9207 §2) and is written here from the tenant all the same, so that the
     * document names its issuer whatever the answer carried.
     *
     * @return non-empty-array<string, mixed>
     */
    public function claims(): array
    {
        $claims = $this->parameters;
        $claims['iss'] = (string) $this->issuer;
        $claims['aud'] = $this->audience;
        $claims['exp'] = $this->expiresAt->getTimestamp();

        return $claims;
    }
}
