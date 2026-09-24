<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use function base64_decode;
use function explode;
use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use function preg_match;
use function str_contains;
use function urldecode;

/**
 * "client_secret_basic" (RFC 6749 §2.3.1, RFC 7617 §2): the identifier and the secret, form-urlencoded,
 * joined by a colon and Basic-encoded in the Authorization header. The method every OAuth 2.0 client
 * knows, and the one Symfony's own client sends by default.
 */
final readonly class ClientSecretBasic extends HashedSecretMethod
{
    public function name(): string
    {
        return 'client_secret_basic';
    }

    public function mechanism(): string
    {
        return ClientAuthenticationRequest::AUTHORIZATION_HEADER;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        $credentials = $this->credentials($request);

        return $credentials === null ? null : $credentials[0];
    }

    protected function presentedSecret(ClientAuthenticationRequest $request): ?string
    {
        $credentials = $this->credentials($request);

        return $credentials === null ? null : $credentials[1];
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
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                null,
                $this->name(),
                'The Basic credentials are malformed.',
            );
        }
        [$clientId, $secret] = explode(':', $decoded, 2);
        $clientId = urldecode($clientId);
        if ($clientId === '') {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                null,
                $this->name(),
                'The Basic credentials are malformed.',
            );
        }

        return [$clientId, urldecode($secret)];
    }
}
