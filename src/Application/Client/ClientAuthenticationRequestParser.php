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

/**
 * What arrived at an endpoint that authenticates a client, read into the request the methods are handed
 * (RFC 6749 §2.3). Reading a request is the job of a parser of the Application, and reading it once is
 * the job of whoever owns the reader: seven methods may be wired and two of them read the assertion,
 * which is read here, before any of them sees the request, and never again.
 *
 * What it refuses is what cannot be read as a client authentication at all, and it refuses it with the
 * failure every refusal of this package travels in, so that the authenticator answers for this one as
 * it answers for every other (RFC 6749 §5.2 "invalid_request").
 */
final readonly class ClientAuthenticationRequestParser
{
    /**
     * RFC 7523 §2.2: the one value of "client_assertion_type".
     */
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * The parameters a client authentication reads, all of them strings: what proves the client
     * (RFC 6749 §2.3.1, RFC 7523 §2.2), and the name it goes by, which is a parameter of the request in
     * its own right.
     */
    private const array CREDENTIAL_PARAMETERS = ['client_id', 'client_secret', 'client_assertion', 'client_assertion_type'];

    public function __construct(
        private CompactJwtReaderInterface $reader,
    ) {
    }

    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake, null when it presented none, which is the ordinary case (RFC 8705 §2)
     *
     * @throws ClientAuthenticationFailure when the request cannot be read as a client authentication
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
     * A request whose credentials are not strings is refused before anything is read, and the audit
     * trail keeps no identifier from it, because none of it can be trusted.
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
     * RFC 7523 §2.2: the assertion the request carries, read and verified in nothing. A request that
     * carries one half of the pair carries neither.
     *
     * @param array<string, mixed> $parameters the credential ones known to be strings
     *
     * @throws ClientAuthenticationFailure when the type is not the one of RFC 7523 §2.2, when one of the
     *                                     two parameters is there without the other, or when the
     *                                     assertion cannot be read
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
                sprintf('The client_assertion_type parameter must be "%s" (RFC 7523 section 2.2).', self::ASSERTION_TYPE),
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
     * @return string|null null when the parameter is absent or empty, an empty credential being no
     *                     credential (RFC 6749 appendix A)
     */
    private static function presented(array $parameters, string $name): ?string
    {
        $value = $parameters[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
