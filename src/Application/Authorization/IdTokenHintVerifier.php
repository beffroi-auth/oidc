<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use function array_key_exists;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Port\JwsVerifierInterface;
use Beffroi\Oidc\Domain\Authorization\IdTokenHint;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\TokenAudience;
use Beffroi\Oidc\Exception\InvalidRequestException;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §3.1.2.1, RP-Initiated Logout §2, RFC 8725 §3.11
 *
 * "exp" is not checked: a hint may describe a past session. A hint with a "typ" is refused: an ID token of this
 * provider carries none, and its access tokens, logout tokens and signed introspection responses name theirs.
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
     * @throws InvalidRequestException
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
            $jws = $this->verifier->verify($tenant, $idTokenHint);
            $claims = self::decode($jws->payload, $redirectable);
        } catch (InvalidJwsException|JsonException $exception) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable, $exception);
        }
        if (array_key_exists('typ', $jws->protectedHeader)) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, $redirectable);
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

        return new IdTokenHint($subject, TokenAudience::valuesOf($claims['aud'] ?? null) ?? [], self::sessionId($claims['sid'] ?? null, $redirectable));
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
