<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use function base64_decode;
use function explode;
use Heidi\Core\Application\Authentication\DecoyHash;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\LogicException;
use function preg_match;
use SensitiveParameter;
use function sprintf;
use function str_contains;
use function urldecode;

/**
 * "client_secret_basic" (RFC 6749 §2.3.1, RFC 7617 §2): the identifier and the secret, form-urlencoded,
 * joined by a colon and Basic-encoded in the Authorization header. The method every OAuth 2.0 client
 * knows, and the one Symfony's own client sends by default.
 */
final readonly class ClientSecretBasic implements SecretKeepingMethodInterface, AuthenticationMethodInterface
{
    public function __construct(
        private PasswordHasherInterface $hasher,
        private DecoyHash $decoy,
    ) {
    }

    public function name(): string
    {
        return 'client_secret_basic';
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function keep(#[SensitiveParameter] string $secret, PasswordHasherInterface $hasher): ClientSecretInterface
    {
        return new HashedClientSecret($hasher->hash($secret));
    }

    public function accepts(ClientSecretInterface $secret): bool
    {
        return $secret instanceof HashedClientSecret;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        $credentials = $this->credentials($request);

        return $credentials === null ? null : $credentials[0];
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $credentials = $this->credentials($request);
        $secret = $client->secret;
        if ($credentials === null || ! $secret instanceof HashedClientSecret) {
            throw new LogicException(sprintf('The client "%s" is not authenticated by %s here.', $client->clientId, $this->name()));
        }
        if (! $this->hasher->verify($secret->hash, $credentials[1])) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidSecret, $client->clientId, $this->name());
        }
    }

    public function payRefusal(ClientAuthenticationRequest $request): void
    {
        $credentials = $this->credentials($request);
        if ($credentials !== null) {
            $this->decoy->verify($credentials[1]);
        }
    }

    /**
     * RFC 7235 §2.1: the scheme is case-insensitive and followed by at least one space. A header that is
     * not this one belongs to another method, or to none.
     *
     * @throws ClientAuthenticationFailure when the header is Basic and its credentials cannot be read
     * @return array{string, string}|null
     */
    private function credentials(ClientAuthenticationRequest $request): ?array
    {
        $header = $request->authorizationHeader;
        if ($header === null || preg_match('/^Basic[ \t]+(\S*)$/i', $header, $matches) !== 1) {
            return null;
        }
        $decoded = base64_decode($matches[1], true);
        if ($decoded === false || ! str_contains($decoded, ':')) {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, null, $this->name(), 'The Basic credentials are malformed.');
        }
        [$clientId, $secret] = explode(':', $decoded, 2);
        $clientId = urldecode($clientId);
        if ($clientId === '') {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, null, $this->name(), 'The Basic credentials are malformed.');
        }

        return [$clientId, urldecode($secret)];
    }
}
