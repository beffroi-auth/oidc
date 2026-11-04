<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * JARM §2.1, §2.4
 */
final readonly class ResponseDocument
{
    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters "state" and "iss" included
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
     * JARM §2.1
     *
     * "iss" is written from the tenant even though the parameters carry it, so that the document names its issuer
     * whatever the answer carried.
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
