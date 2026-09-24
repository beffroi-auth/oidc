<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use function array_all;
use function array_is_list;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Domain\Authorization\IdTokenHint;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use Symfony\Component\Uid\Uuid;

/**
 * Reads an id_token_hint (OIDC Core §3.1.2.1, RP-Initiated Logout §2): signed by a published key of the
 * tenant, "iss" equal to the issuer, a valid "sub" and "sid". "exp" is not looked at, the hint may
 * describe a past session. verify() also checks "aud" for the authorization endpoint; the logout endpoint
 * calls read() and finds the client in "aud" itself.
 */
final readonly class IdTokenHintVerifier
{
    private const string NOT_ISSUED_HERE = 'The id_token_hint parameter is not an ID token issued by this provider.';

    private const string NOT_FOR_CLIENT = 'The id_token_hint parameter is not an ID token issued to this client.';

    /**
     * Deeper than an "address" object inside the claims was not issued here.
     */
    private const int MAX_DEPTH = 4;

    public function __construct(
        private JwsVerifierInterface $verifier,
    ) {
    }

    /**
     * @throws InvalidRequestException always redirectable
     */
    public function verify(Client $client, string $idTokenHint): Subject
    {
        $hint = $this->read($client->tenant, $idTokenHint, true);
        if (! $hint->isFor($client->registration->clientId)) {
            throw new InvalidRequestException(self::NOT_FOR_CLIENT, true);
        }

        return $hint->subject;
    }

    /**
     * @throws InvalidRequestException
     */
    public function read(Tenant $tenant, string $idTokenHint, bool $redirectable): IdTokenHint
    {
        try {
            $claims = self::decode($this->verifier->verify($tenant, $idTokenHint)->payload, $redirectable);
        } catch (InvalidJwsException|JsonException $exception) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable, $exception);
        }
        if (! isset($claims['iss']) || $claims['iss'] !== (string) $tenant->issuer) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
        }
        if (! isset($claims['sub']) || ! is_string($claims['sub'])) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
        }
        try {
            $subject = new Subject($claims['sub']);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
        }

        return new IdTokenHint($subject, self::audiences($claims['aud'] ?? null), self::sessionId($claims['sid'] ?? null, $redirectable));
    }

    /**
     * @throws JsonException
     * @return array<array-key, mixed>
     */
    private static function decode(string $payload, bool $redirectable): array
    {
        $claims = json_decode($payload, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        if (! is_array($claims)) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
        }

        return $claims;
    }

    /**
     * OIDC Core §2 "aud": a string or a list of strings.
     *
     * @return list<string>
     */
    private static function audiences(mixed $aud): array
    {
        if (is_string($aud)) {
            return [$aud];
        }
        if (is_array($aud) && array_is_list($aud) && array_all($aud, static fn (mixed $value): bool => is_string($value))) {
            /** @var list<string> $aud */
            return $aud;
        }

        return [];
    }

    /**
     * An RFC 9562 UUID, as this provider writes it (architecture §4.6).
     */
    private static function sessionId(mixed $sid, bool $redirectable): ?Uuid
    {
        if ($sid === null) {
            return null;
        }
        if (! is_string($sid) || ! Uuid::isValid($sid, Uuid::FORMAT_RFC_9562)) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
        }

        return Uuid::fromString($sid);
    }
}
