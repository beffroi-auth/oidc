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
 * What an endpoint reads when the request came in a JWT (RFC 9101 §6.1, OIDC Core §6): "request" carries
 * the object, "request_uri" names where it is published, and the two together are no request at all.
 * The parameters of the object are the request; the ones of the query are dropped, which is §6.1 read as
 * it is written, so that what the client signed and what the provider reads are the same request. Only
 * "client_id" stays, because RFC 9101 §5 has it outside the object as well and the two must be one.
 *
 * An object a client encrypted to a key the tenant publishes is opened before it is read, and what comes
 * out of the JWE goes on exactly as an object that arrived in clear (RFC 9101 §6.1): being encrypted
 * says who may read the request, never who wrote it.
 *
 * Nothing of the object is trusted before its signature is: the algorithm is the one the client
 * registered, the key is one the client publishes, and an object signed with nothing is read only from a
 * client that registered "none" (decision 0006). A "request_uri" is read back only when the client
 * registered that very URL, which is what "require_request_uri_registration" announces: an unregistered
 * one is refused before any request leaves the process.
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
     * @param array<string, mixed> $parameters the parameters of the request as the endpoint received them
     * @param Client|null $client the client the endpoint has already authenticated (RFC 9126 §2), null
     *                            at an endpoint that authenticates none and reads "client_id" instead
     *
     * @throws OAuth2Exception never redirectable: what names the destination is inside the object, and
     *                         an object that is refused is an object that was not read
     *
     * @return ResolvedRequestObject|null the object and the parameters the endpoint reads in place of
     *                                     them, null when the request carries no object and the ones it
     *                                     carries stand
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
     * RFC 9101 §5: "client_id" is a parameter of the request itself and is there whether the object
     * carries one or not, because the provider has to know whose keys to verify the object with before
     * it reads anything of it.
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
     * RFC 9101 §6.2: the signature, under the algorithm the client registered and against the keys the
     * client publishes. An object a client registered "none" for carries no signature, and there is
     * nothing to verify; every other one is verified under the one algorithm that was accepted, never
     * under whichever of them the object names.
     *
     * @throws OAuth2Exception
     */
    private function verify(Client $client, RequestObject $object): void
    {
        $algorithm = $object->jwt->algorithm();
        if ($algorithm === null || ! $client->registration->requestObjectSigning->accepts($algorithm, $this->wiredAlgorithms())) {
            // The "alg" of the object is not written back: it is a string the sender chose, and an error
            // description is ASCII the specification bounds (RFC 6749 §5.2)
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
     * RFC 9101 §5.2, OIDC Core §6.2: read back from the URL the client registered and from no other.
     * The URL is compared with the registration before anything leaves the process, so an unregistered
     * one costs the provider one comparison and no request at all (decision 0006). What is compared is
     * the URI the client registered, fragment included, and what is read is the URL without it: §6.2
     * gives that fragment a meaning, and a fragment is never sent to a server (RequestUri).
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
