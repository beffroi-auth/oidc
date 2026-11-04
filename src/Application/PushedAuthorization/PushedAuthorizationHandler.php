<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\PushedAuthorization;

use Beffroi\Oidc\Application\Secret\SecretDrawer;
use DateInterval;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Authorization\AuthorizationRequestParser;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Application\Client\ClientAuthenticator;
use Beffroi\Oidc\Application\Dpop\DpopProofVerifier;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationResponse;
use Beffroi\Oidc\Domain\PushedAuthorization\RequestUri;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Beffroi\Oidc\Port\EndpointLocatorInterface;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use function array_all;
use function array_is_list;
use function is_array;
use function is_string;
use Psr\Clock\ClockInterface;

/**
 * RFC 9126 §2
 */
final readonly class PushedAuthorizationHandler
{
    /**
     * RFC 6749 §2.3.1, RFC 7523 §2.2
     *
     * "client_id" is not one of them: it is a parameter of the authorization request in its own right.
     */
    private const array PROVING_PARAMETERS = ['client_secret', 'client_assertion', 'client_assertion_type'];

    public function __construct(
        private ClientAuthenticator $clients,
        private DpopProofVerifier $proofs,
        private EndpointLocatorInterface $endpoints,
        private AuthorizationRequestParser $parser,
        private RequestObjectResolver $requestObjects,
        private PushedAuthorizationRecordRepositoryInterface $records,
        private SecretDrawer $secrets,
        private ClockInterface $clock,
        public DateInterval $lifetime = new DateInterval('PT60S'),
    ) {
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @throws OAuth2Exception
     */
    public function handle(
        Tenant $tenant,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate = null,
        ?string $dpopProof = null,
    ): PushedAuthorizationResponse {
        $endpoint = $this->endpoints->locate($tenant)->pushedAuthorizationRequest;
        $client = $this->clients->authenticate($tenant, $endpoint, $authorizationHeader, $parameters, $context, $certificate)->client;
        $provenKey = $this->proofs->verify($dpopProof, 'POST', $endpoint, $context->receivedAt);
        if (RequestParameters::of($parameters)->isPresent('request_uri')) {
            throw new InvalidRequestException('The request_uri parameter is not one of those a pushed authorization request carries (RFC 9126 section 2.1).');
        }

        // RFC 9126 §2.1: a "client_id" naming another client was already refused, and Basic auth sends none.
        $parameters['client_id'] = $client->registration->clientId;
        $object = $this->requestObjects->resolve($tenant, $parameters, $client);
        $parameters = $object->parameters ?? $parameters;
        $parameters = self::reservedFor($parameters, $provenKey);
        $target = $this->parser->redirectTarget($tenant, $parameters, true, $object !== null);
        $this->parser->parse($target, $parameters);

        $now = $this->clock->now();
        $requestUri = RequestUri::of($this->secrets->draw());
        $record = new PushedAuthorizationRecord($requestUri->hash(), $client, self::kept($parameters), $now, $now->add($this->lifetime), $object !== null);
        $this->records->save($record);

        return new PushedAuthorizationResponse($requestUri, $record->expiresIn($now));
    }

    /**
     * RFC 9449 §10.1
     *
     * @param array<string, mixed> $parameters
     *
     * @throws InvalidRequestException when the request names one key and the proof another
     *
     * @return array<string, mixed>
     */
    private static function reservedFor(array $parameters, ?KeyConfirmation $provenKey): array
    {
        if ($provenKey === null) {
            return $parameters;
        }
        $named = $parameters['dpop_jkt'] ?? null;
        if (is_string($named) && $named !== '' && $named !== $provenKey->thumbprint) {
            throw new InvalidRequestException('The dpop_jkt of the pushed request names another key than the proof that carried it (RFC 9449 section 10.1).');
        }
        $parameters['dpop_jkt'] = $provenKey->thumbprint;

        return $parameters;
    }

    /**
     * RFC 9126 §2.1
     *
     * @param array<string, mixed> $parameters
     *
     * @return array<string, string|list<string>>
     */
    private static function kept(array $parameters): array
    {
        foreach (self::PROVING_PARAMETERS as $name) {
            unset($parameters[$name]);
        }
        $kept = [];
        foreach ($parameters as $name => $value) {
            if (is_string($value)) {
                $kept[$name] = $value;

                continue;
            }
            if (is_array($value) && array_is_list($value) && array_all($value, static fn (mixed $item): bool => is_string($item))) {
                /** @var list<string> $value */
                $kept[$name] = $value;
            }
        }

        return $kept;
    }
}
