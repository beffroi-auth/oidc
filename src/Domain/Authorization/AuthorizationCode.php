<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use function base64_encode;
use DateTimeImmutable;
use function hash;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function preg_match;
use function random_bytes;
use function rtrim;
use SensitiveParameter;
use function strtr;

/**
 * An authorization code (RFC 6749 §1.3.1, §4.1.2) as the provider keeps it: the SHA-256 of the value the
 * client received, never the value itself, and everything the token endpoint will need to answer the
 * grant (architecture §4.4). "authenticatedAt", the methods and the context class are copied from the
 * session at issuance: the ID token describes the authentication the code was issued after, not a proof
 * added later.
 *
 * Lifetime: 60 seconds. RFC 6749 §4.1.2 allows up to 10 minutes; a code only serves an immediate round
 * trip, and a short window bounds injection (RFC 9700 §4.5). A code is consumed by its first presentation
 * at the token endpoint, whatever comes of it (architecture §4.4); a second presentation is a replay, and
 * what the grant does about it is its business.
 */
final class AuthorizationCode
{
    public const string HASH_PATTERN = '/^[0-9a-f]{64}$/';

    public readonly Tenant $tenant;

    /**
     * The client, named the way a registration names it: the object is what the client repository resolved
     * for that identifier, and what a store keeps is the identifier.
     */
    public readonly string $clientId;

    /**
     * @var non-empty-list<Scope>
     */
    public readonly array $scopes;

    /**
     * @var non-empty-list<string> the "amr" values
     */
    public readonly array $authenticationMethods;

    public private(set) ?DateTimeImmutable $usedAt = null;

    /**
     * @param string $codeHash hex SHA-256 of the code, see hash()
     * @param RedirectUri $redirectUri the one of the request, compared again at the token endpoint (RFC 6749 §4.1.3)
     * @param list<Scope> $scopes the scopes granted, at least one
     * @param string|null $nonce copied into the ID token (OIDC Core §3.1.3.7 step 11)
     * @param CodeChallenge|null $codeChallenge verified against the code_verifier (RFC 7636 §4.6); null when the request carried none, which only a client that does not require PKCE may do (decision 0008), and then a code_verifier is refused (RFC 9700 §4.8.2)
     * @param DateTimeImmutable $authenticatedAt the "auth_time" the ID token will carry
     * @param list<string> $authenticationMethods the "amr" values, at least one
     * @param string|null $authenticationContextClass the "acr" value
     */
    public function __construct(
        public readonly string $codeHash,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        public readonly RedirectUri $redirectUri,
        array $scopes,
        public readonly ?string $nonce,
        public readonly ?CodeChallenge $codeChallenge,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly DateTimeImmutable $authenticatedAt,
        array $authenticationMethods,
        public readonly ?string $authenticationContextClass,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (preg_match(self::HASH_PATTERN, $codeHash) !== 1) {
            throw new InvalidArgumentException('An authorization code is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization code binds a session and a client of the same tenant.');
        }
        if ($scopes === []) {
            throw new InvalidArgumentException('An authorization code grants at least one scope.');
        }
        if ($authenticationMethods === []) {
            throw new InvalidArgumentException('An authorization code records at least one authentication method (RFC 8176).');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An authorization code expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->clientId;
        $this->scopes = $scopes;
        $this->authenticationMethods = $authenticationMethods;
    }

    /**
     * A fresh code: 256 bits from the CSPRNG, base64url without padding (43 characters).
     */
    public static function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * How a code is stored and looked up: a leaked table of codes yields nothing usable.
     */
    public static function hash(#[SensitiveParameter] string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * The first presentation at the token endpoint, valid or not, consumes the code (RFC 6749 §4.1.2:
     * "The client MUST NOT use the authorization code more than once"). The grant reads isUsed() before
     * calling this: a replay is its decision, not a state error.
     */
    public function consume(DateTimeImmutable $now): void
    {
        if ($this->usedAt !== null) {
            throw new LogicException('An authorization code is consumed once; the grant checks isUsed() first.');
        }
        $this->usedAt = $now;
    }

    public function isUsed(): bool
    {
        return $this->usedAt !== null;
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
