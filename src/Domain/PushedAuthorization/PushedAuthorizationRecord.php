<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\PushedAuthorization;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\PersonalData\Sealed;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Record\RecordReadOnce;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function max;

/**
 * RFC 9126 §2
 */
final class PushedAuthorizationRecord extends RecordReadOnce implements ResolvesItsClientInterface
{
    public readonly Tenant $tenant;

    public readonly string $clientId;

    /**
     * @param array<string, string|list<string>> $parameters as the client pushed them, its credentials taken out
     */
    public function __construct(
        public readonly string $requestUriHash,
        public readonly Client $client,
        public readonly array $parameters,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly bool $carriedBySignedObject = false,
    ) {
        if (! DrawnSecret::isDigest($requestUriHash)) {
            throw new InvalidArgumentException('A pushed authorization request is stored as the hex SHA-256 of its request URI.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('A pushed authorization request expires after it was pushed.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    /**
     * RFC 9126 §2.2
     *
     * @return positive-int
     */
    public function expiresIn(DateTimeImmutable $now): int
    {
        return max(1, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }

    public function belongsTo(Client $client): bool
    {
        return $this->clientId === $client->registration->clientId && $this->tenant->equals($client->tenant);
    }

    protected function nameOfRecord(): string
    {
        return 'A pushed authorization request';
    }

    protected function readerThatChecks(): string
    {
        return 'the authorization endpoint';
    }

    public function clientHolder(): object
    {
        return $this;
    }

    /**
     * The parameters are sealed whole: they carry the hints of the request word for word.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'parameters' => new Sealed('pushed_authorization_request'),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'carriedBySignedObject' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'requestUriHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
        ];
    }
}
