<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use function is_string;
use function sprintf;

final readonly class ClientAuthenticationRequestParser
{
    /**
     * RFC 7523 §2.2
     */
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    private const array CREDENTIAL_PARAMETERS = ['client_id', 'client_secret', 'client_assertion', 'client_assertion_type'];

    public function __construct(
        private CompactJwtReaderInterface $reader,
    ) {
    }

    /**
     * @param string $endpoint absolute URL
     * @param array<string, mixed> $parameters
     *
     * @throws ClientAuthenticationFailure
     */
    public function read(
        Tenant $tenant,
        string $endpoint,
        ?string $authorizationHeader,
        array $parameters,
        RequestContext $context,
        ?ClientCertificate $certificate,
    ): ClientAuthenticationRequest {
        $this->refuseCredentialsThatAreNotStrings($parameters);

        return new ClientAuthenticationRequest(
            $tenant,
            $endpoint,
            $authorizationHeader,
            $parameters,
            $context,
            $certificate,
            $this->assertionIn($parameters),
        );
    }

    /**
     * The audit trail keeps no identifier of such a request: none of it can be trusted.
     *
     * @param array<string, mixed> $parameters
     *
     * @throws ClientAuthenticationFailure
     */
    private function refuseCredentialsThatAreNotStrings(array $parameters): void
    {
        foreach (self::CREDENTIAL_PARAMETERS as $name) {
            $value = $parameters[$name] ?? null;
            if ($value !== null && ! is_string($value)) {
                throw ClientAuthenticationFailure::malformedRequest(
                    ClientAuthenticationFailureReason::MalformedCredentials,
                    null,
                    null,
                    sprintf('The %s parameter must be a string.', $name),
                );
            }
        }
    }

    /**
     * RFC 7523 §2.2
     *
     * @param array<string, mixed> $parameters
     *
     * @throws ClientAuthenticationFailure when the pair is incomplete, of another type or unreadable
     */
    private function assertionIn(array $parameters): ?UnverifiedJwt
    {
        $assertion = self::presented($parameters, 'client_assertion');
        $type = self::presented($parameters, 'client_assertion_type');
        if ($assertion === null && $type === null) {
            return null;
        }
        $clientId = self::presented($parameters, 'client_id');
        if ($assertion === null || $type === null) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $clientId,
                null,
                'The client_assertion and client_assertion_type parameters go together (RFC 7523 section 2.2).',
            );
        }
        if ($type !== self::ASSERTION_TYPE) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $clientId,
                null,
                sprintf('The client_assertion_type parameter must be %s (RFC 7523 section 2.2).', self::ASSERTION_TYPE),
            );
        }

        try {
            return $this->reader->read($assertion);
        } catch (InvalidJwtException $exception) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $clientId,
                null,
                'The client assertion is not a readable JWT (RFC 7523 section 2.2).',
                $exception,
            );
        }
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return string|null null when absent or empty
     */
    private static function presented(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
