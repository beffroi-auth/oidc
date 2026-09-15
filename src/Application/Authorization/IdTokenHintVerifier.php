<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use function array_is_list;
use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use JsonException;

/**
 * Reads whom an id_token_hint names (OIDC Core §3.1.2.1). The token must be one this provider signed
 * for this client: signature against the published keys of the tenant, "iss" equal to the issuer, "aud"
 * containing the client identifier. "exp" is not looked at: the hint may describe a past session, and a
 * client keeps the last ID token it received. A hint that fails any of this is refused as invalid_request
 * rather than ignored, so that a client never learns anything from a token it did not obtain here.
 */
final readonly class IdTokenHintVerifier
{
    private const string NOT_ISSUED_HERE = 'The id_token_hint parameter is not an ID token issued by this provider.';

    private const string NOT_FOR_CLIENT = 'The id_token_hint parameter is not an ID token issued to this client.';

    /**
     * An ID token payload nests at most an object of claims holding an "address" object; anything deeper
     * was not issued here.
     */
    private const int MAX_DEPTH = 4;

    public function __construct(
        private JwsVerifierInterface $verifier,
    ) {
    }

    /**
     * @throws InvalidRequestException always redirectable: the hint is read after the client and its redirect URI
     * @return Subject the "sub" the hint names
     */
    public function verify(Client $client, string $idTokenHint): Subject
    {
        try {
            $claims = self::decode($this->verifier->verify($client->tenant, $idTokenHint)->payload);
        } catch (InvalidJwsException|JsonException $exception) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, true, $exception);
        }
        if (! isset($claims['iss']) || $claims['iss'] !== (string) $client->tenant->issuer) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, true);
        }
        if (! self::isAudience($claims['aud'] ?? null, $client->clientId)) {
            throw new InvalidRequestException(self::NOT_FOR_CLIENT, true);
        }
        if (! isset($claims['sub']) || ! is_string($claims['sub'])) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, true);
        }
        try {
            return new Subject($claims['sub']);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, true);
        }
    }

    /**
     * The claims of an ID token are a JSON object (OIDC Core §2); a list has no "iss" and is refused
     * further down like any other.
     *
     * @throws JsonException
     * @return array<array-key, mixed>
     */
    private static function decode(string $payload): array
    {
        $claims = json_decode($payload, true, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        if (! is_array($claims)) {
            throw new InvalidRequestException(self::NOT_ISSUED_HERE, true);
        }

        return $claims;
    }

    /**
     * OIDC Core §2 "aud": a single string or a list of strings.
     */
    private static function isAudience(mixed $aud, string $clientId): bool
    {
        if (is_string($aud)) {
            return $aud === $clientId;
        }

        return is_array($aud) && array_is_list($aud) && in_array($clientId, $aud, true);
    }
}
