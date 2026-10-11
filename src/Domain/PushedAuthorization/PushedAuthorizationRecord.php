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
 * What the provider keeps of an authorization request a client pushed before sending its user
 * (RFC 9126 §2): the SHA-256 of the reference it answered with, the client the record is bound to
 * (§2.2), and the parameters the authorization endpoint will read in place of the query (§4). It is a
 * record and not a request: a request is what a client sent, and this outlives it, with a lifetime, a
 * use and a state of its own. The parameters are kept as the client wrote them and not as the parser
 * understood them, so that the endpoint reads one request whichever way it arrived; what authenticated
 * the client at the endpoint is not among them.
 *
 * The record is read once: the repository claims it atomically and the winner consumes it, as it does an
 * authorization code. A consumed or expired record grants nothing and stays only so that the next
 * presentation is told from a reference nobody ever issued.
 */
final class PushedAuthorizationRecord extends RecordReadOnce implements ResolvesItsClientInterface
{
    public readonly Tenant $tenant;

    /**
     * What a store keeps; the object is what the client repository resolved for it.
     */
    public readonly string $clientId;

    /**
     * @param string $requestUriHash see RequestUri::hashOf()
     * @param array<string, string|list<string>> $parameters the form parameters the client pushed, credentials taken out; a parameter the client repeated is kept as the list it was (RFC 8707 §2)
     * @param bool $carriedBySignedObject whether the push carried a request object the client signed
     *                                    (RFC 9101 §6.1), which the authorization endpoint can no longer
     *                                    see once the record answers for the request
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
     * RFC 9126 §2.2: a positive number of seconds, rounded up so that the client is never told a
     * lifetime longer than the one the record has.
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
     * The parameters are sealed whole: they carry the hints of the request they stand for, word for word
     * (RFC 9126 §2.2).
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
