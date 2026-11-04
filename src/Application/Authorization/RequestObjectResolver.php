<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Authorization;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Authorization\RequestObject;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\InvalidRequestObjectException;
use Beffroi\Oidc\Exception\InvalidRequestUriException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use Psr\Clock\ClockInterface;

/**
 * RFC 9101 §6.1, OIDC Core §6
 *
 * The query's parameters are dropped, never merged, so the provider reads exactly what the client signed.
 */
final readonly class RequestObjectResolver
{
    public function __construct(
        private ClientRepositoryInterface $clients,
        private RequestObjectReader $objects,
        private JwtKeyVerifierInterface $signatures,
        private ClientKeySetProvider $keys,
        private RequestObjectValidator $claims,
        private RequestObjectFetcherInterface $references,
        private SignatureAlgorithmsInterface $algorithms,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception never redirectable
     */
    public function resolve(Tenant $tenant, array $parameters, ?Client $client = null): ?ResolvedRequestObject
    {
        $received = RequestParameters::of($parameters);
        $byValue = $received->optional('request');
        $byReference = $received->optional('request_uri');
        if ($byValue === null && $byReference === null) {
            return null;
        }
        if ($byValue !== null && $byReference !== null) {
            throw new InvalidRequestException('The request and request_uri parameters are never sent together (OIDC Core section 6).');
        }
        $client ??= $this->client($tenant, $parameters);
        $object = $this->objects->read($tenant, $byReference === null ? $byValue : $this->fetch($client, $byReference));
        $this->verify($client, $object);
        $this->claims->validate($object, $client, $tenant, $this->clock->now());

        return new ResolvedRequestObject($object, [
            ...$object->parameters(),
            'client_id' => $client->registration->clientId,
        ]);
    }

    /**
     * RFC 9101 §5
     *
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception
     */
    private function client(Tenant $tenant, array $parameters): Client
    {
        return (
            $this->clients->findByClientId(
                $tenant,
                RequestParameters::of($parameters)->clientId(),
            ) ?? throw new InvalidRequestException('The client is unknown.')
        );
    }

    /**
     * RFC 9101 §6.2
     *
     * The verifier is given the one algorithm accepted, never a list the header could choose from.
     *
     * @throws OAuth2Exception
     */
    private function verify(Client $client, RequestObject $object): void
    {
        $algorithm = $object->jwt->algorithm();
        if ($algorithm === null || ! $client->registration->requestObjectSigning->accepts($algorithm, $this->wiredAlgorithms())) {
            // The "alg" is not written back: a description never echoes what the sender chose (RFC 6749 §5.2).
            throw new InvalidRequestObjectException('The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).');
        }
        if ($algorithm === UnsignedRequestObjects::ALGORITHM) {
            return;
        }
        try {
            $keys = $this->keys->keysOf($client, $object->jwt->keyId());
        } catch (ClientKeysUnavailableException $exception) {
            throw new InvalidRequestObjectException('The keys of the client cannot be read, and its request object cannot be verified.', $exception);
        }
        try {
            $this->signatures->verify($object->jwt, $keys, [$algorithm]);
        } catch (InvalidJwtException $exception) {
            throw new InvalidRequestObjectException('The signature of the request object verifies against no key the client publishes.', $exception);
        }
    }

    /**
     * RFC 9101 §5.2, OIDC Core §6.2
     *
     * @throws OAuth2Exception
     */
    private function fetch(Client $client, string $requestUri): string
    {
        $registered = $client->registration->registeredRequestUri($requestUri);
        if ($registered === null) {
            throw new InvalidRequestUriException('The request_uri parameter names no URL this client registered (OIDC Discovery section 3, require_request_uri_registration).');
        }
        try {
            return $this->references->fetch($registered->location);
        } catch (RequestObjectUnavailableException $exception) {
            throw new InvalidRequestUriException('The request object behind the request_uri parameter cannot be read back.', $exception);
        }
    }

    /**
     * @return list<non-empty-string>
     */
    private function wiredAlgorithms(): array
    {
        return AlgorithmNames::of($this->algorithms->all());
    }
}
