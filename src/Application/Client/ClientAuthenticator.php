<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use function base64_decode;
use function explode;
use Heidi\Core\Domain\Credential\PasswordHash;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailed;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\InvalidClientException;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\OAuth2Exception;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use function is_string;
use function preg_match;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use function sprintf;
use function str_contains;
use Symfony\Component\Uid\Uuid;
use function urldecode;

/**
 * Authenticates the client of a token request (RFC 6749 §2.3.1, §3.2.1). The Authorization header is read
 * first (client_secret_basic), then the form parameters (client_secret_post), then a bare client_id (a
 * public client, "none"). Using both a header and a body secret is "invalid_request"; an unknown client, a
 * method other than the registered one or a wrong secret is "invalid_client", answered 401 with a
 * WWW-Authenticate challenge when the header was used (RFC 6749 §5.2).
 *
 * A presented secret is always verified once, against the client's hash or against a decoy, so that the
 * time taken does not tell an unknown client from a known one. The hasher compares in constant time.
 */
final class ClientAuthenticator
{
    /**
     * One description once a client identifier is involved: whether the client exists, which method it
     * registered and whether the secret was close are for the audit trail, not for the caller.
     */
    private const string FAILED = 'Client authentication failed.';

    private ?PasswordHash $decoyHash = null;

    public function __construct(
        private readonly ClientRepositoryInterface $clients,
        private readonly PasswordHasherInterface $hasher,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
    ) {
    }

    /**
     * @param string|null $authorizationHeader the Authorization request header, if any
     * @param array<string, mixed> $parameters the form parameters of the request body
     *
     * @throws OAuth2Exception
     */
    public function authenticate(Tenant $tenant, ?string $authorizationHeader, array $parameters, RequestContext $context): Client
    {
        $challenge = null;
        $basic = null;
        if ($authorizationHeader !== null) {
            $challenge = sprintf('Basic realm="%s"', $tenant->issuer);
            // RFC 7235 §2.1: the scheme is case-insensitive and is followed by at least one space
            if (preg_match('/^Basic[ \t]+(\S*)$/i', $authorizationHeader, $matches) !== 1) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::UnsupportedScheme, null, null, new InvalidClientException('The Authorization header must use the Basic scheme.', $challenge));
            }
            $basic = self::decodeBasic($matches[1]);
            if ($basic === null) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::MalformedCredentials, null, TokenEndpointAuthMethod::ClientSecretBasic, new InvalidRequestException('The Basic credentials are malformed.'));
            }
        }

        $bodyClientId = $parameters['client_id'] ?? null;
        $bodySecret = $parameters['client_secret'] ?? null;
        if (($bodyClientId !== null && ! is_string($bodyClientId)) || ($bodySecret !== null && ! is_string($bodySecret))) {
            throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::MalformedCredentials, $basic[0] ?? null, null, new InvalidRequestException('The client_id and client_secret parameters must be strings.'));
        }

        if ($basic !== null) {
            if ($bodySecret !== null) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::MultipleMechanisms, $basic[0], null, new InvalidRequestException('The client must not use more than one authentication method in a request.'));
            }
            if ($bodyClientId !== null && $bodyClientId !== $basic[0]) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::MismatchedClientId, $basic[0], TokenEndpointAuthMethod::ClientSecretBasic, new InvalidRequestException('The client_id parameter does not match the Authorization header.'));
            }
            [$clientId, $secret] = $basic;
            $method = TokenEndpointAuthMethod::ClientSecretBasic;
        } elseif ($bodySecret !== null) {
            if ($bodyClientId === null) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::MalformedCredentials, null, TokenEndpointAuthMethod::ClientSecretPost, new InvalidRequestException('The client_secret parameter requires a client_id parameter.'));
            }
            $clientId = $bodyClientId;
            $secret = $bodySecret;
            $method = TokenEndpointAuthMethod::ClientSecretPost;
        } elseif ($bodyClientId !== null) {
            $clientId = $bodyClientId;
            $secret = null;
            $method = TokenEndpointAuthMethod::None;
        } else {
            throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::NoCredentials, null, null, new InvalidClientException('The request carries no client authentication.'));
        }

        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client === null) {
            $this->verifyDecoy($secret);

            throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::UnknownClient, $clientId, $method, new InvalidClientException(self::FAILED, $challenge));
        }
        if ($client->tokenEndpointAuthMethod !== $method) {
            $this->verifyDecoy($secret);

            throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::UnexpectedMethod, $clientId, $method, new InvalidClientException(self::FAILED, $challenge));
        }
        if ($secret !== null) {
            /** @var PasswordHash $hash a confidential client always has one */
            $hash = $client->secretHash;
            if (! $this->hasher->verify($hash, $secret)) {
                throw $this->failure($tenant, $context, ClientAuthenticationFailureReason::InvalidSecret, $clientId, $method, new InvalidClientException(self::FAILED, $challenge));
            }
        }

        return $client;
    }

    /**
     * RFC 6749 §2.3.1: the client identifier and the secret are each form-urlencoded, joined by a colon,
     * then Basic-encoded (RFC 7617 §2). Decoded here in the reverse order.
     *
     * @return array{string, string}|null the identifier and the secret, or null when the credentials cannot be read
     */
    private static function decodeBasic(string $credentials): ?array
    {
        $decoded = base64_decode($credentials, true);
        if ($decoded === false || ! str_contains($decoded, ':')) {
            return null;
        }
        [$clientId, $secret] = explode(':', $decoded, 2);
        $clientId = urldecode($clientId);
        if ($clientId === '') {
            return null;
        }

        return [$clientId, urldecode($secret)];
    }

    /**
     * Same cost as a real verification when there is nothing to verify against.
     */
    private function verifyDecoy(#[SensitiveParameter] ?string $secret): void
    {
        if ($secret === null) {
            return;
        }
        $this->decoyHash ??= $this->hasher->hash(Uuid::v4()->toRfc4122());
        $this->hasher->verify($this->decoyHash, $secret);
    }

    private function failure(
        Tenant $tenant,
        RequestContext $context,
        ClientAuthenticationFailureReason $reason,
        ?string $clientId,
        ?TokenEndpointAuthMethod $method,
        OAuth2Exception $exception,
    ): OAuth2Exception {
        $this->events->dispatch(new ClientAuthenticationFailed($this->clock->now(), $tenant, $context, $reason, $clientId, $method));

        return $exception;
    }
}
