<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\UnverifiedJwt;
use Heidi\Oidc\Exception\InvalidJwtException;
use Heidi\Oidc\Port\CompactJwtReaderInterface;
use function is_string;
use function sprintf;

/**
 * One request at an endpoint that authenticates a client (RFC 6749 §2.3): the header it carries, the
 * form parameters it carries, the certificate its connection proved (RFC 8705 §2), and the URL of the
 * endpoint that received it, which an assertion may name as its audience (RFC 7523 §3). The parameters a
 * client authentication reads are checked to be strings as soon as the request is built: a request whose
 * credentials are not strings is refused before anything is read, and the audit trail keeps no identifier
 * from it, because none of it can be trusted.
 *
 * The constants below name what of a request a method reads. Two methods that read the same one are one
 * mechanism of RFC 6749 §2.3 and not two, which is how the two mutual-TLS methods of RFC 8705 §2 can
 * both take the one certificate the connection carries.
 */
final class ClientAuthenticationRequest
{
    /**
     * RFC 6749 §2.3.1, RFC 7523 §2.2: what a client authentication proves the client with, and what an
     * endpoint keeping a request for later therefore never keeps (RFC 9126 §2.1).
     */
    private const array PROVING_PARAMETERS = ['client_secret', 'client_assertion', 'client_assertion_type'];

    /**
     * The parameters a client authentication reads, all of them strings: what proves the client, and the
     * name it goes by, which is a parameter of the request in its own right.
     */
    private const array CREDENTIAL_PARAMETERS = ['client_id', ...self::PROVING_PARAMETERS];

    /**
     * RFC 7523 §2.2: the one value of "client_assertion_type".
     */
    public const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public const string AUTHORIZATION_HEADER = 'the Authorization header';

    public const string BODY_SECRET = 'the client_secret parameter';

    public const string ASSERTION = 'the client_assertion parameter';

    public const string CERTIFICATE = 'the certificate of the connection';

    public const string IDENTIFIER = 'the client_id parameter';

    private bool $assertionRead = false;

    private ?UnverifiedJwt $assertion = null;

    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request
     * @param array<string, mixed> $parameters the form parameters of the request body
     * @param ClientCertificate|null $certificate the certificate the client presented at the TLS handshake, null when it presented none, which is the ordinary case (RFC 8705 §2)
     *
     * @throws ClientAuthenticationFailure when a credential parameter is present and is not a string
     */
    public function __construct(
        public readonly Tenant $tenant,
        public readonly string $endpoint,
        public readonly ?string $authorizationHeader,
        private readonly array $parameters,
        public readonly RequestContext $context,
        public readonly ?ClientCertificate $certificate = null,
    ) {
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
     * The parameters of a request once what proved the client is taken out of them, for an endpoint that
     * keeps a request the client will come back to (RFC 9126 §2). A credential authenticates the request
     * that carries it and nothing else, and a store holding one would hold a secret it has no use for;
     * "client_id" stays, being a parameter of the authorization request itself.
     *
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    public static function withoutCredentials(array $parameters): array
    {
        foreach (self::PROVING_PARAMETERS as $name) {
            unset($parameters[$name]);
        }

        return $parameters;
    }

    /**
     * @return string|null null when the parameter is absent or empty, an empty credential being no
     *                     credential (RFC 6749 appendix A)
     */
    public function parameter(string $name): ?string
    {
        $value = $this->parameters[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    public function clientId(): ?string
    {
        return $this->parameter('client_id');
    }

    /**
     * RFC 6749 §2.3.1: a secret in the body. An empty one is a secret all the same, presented and wrong,
     * so it is read as it is given.
     */
    public function secret(): ?string
    {
        $value = $this->parameters['client_secret'] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * RFC 7523 §2.2: the assertion of the request, read once whichever method reads it first. A request
     * that carries one half of the pair carries neither.
     *
     * @throws ClientAuthenticationFailure when the type is not the one of RFC 7523 §2.2, when one of the
     *                                     two parameters is there without the other, or when the
     *                                     assertion cannot be read
     */
    public function assertion(CompactJwtReaderInterface $reader): ?UnverifiedJwt
    {
        if ($this->assertionRead) {
            return $this->assertion;
        }
        $this->assertionRead = true;
        $assertion = $this->parameter('client_assertion');
        $type = $this->parameter('client_assertion_type');
        if ($assertion === null && $type === null) {
            return null;
        }
        if ($assertion === null || $type === null) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $this->clientId(),
                null,
                'The client_assertion and client_assertion_type parameters go together (RFC 7523 section 2.2).',
            );
        }
        if ($type !== self::ASSERTION_TYPE) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $this->clientId(),
                null,
                sprintf('The client_assertion_type parameter must be "%s" (RFC 7523 section 2.2).', self::ASSERTION_TYPE),
            );
        }
        try {
            return $this->assertion = $reader->read($assertion);
        } catch (InvalidJwtException $exception) {
            throw ClientAuthenticationFailure::malformedRequest(
                ClientAuthenticationFailureReason::MalformedCredentials,
                $this->clientId(),
                null,
                'The client assertion is not a readable JWT (RFC 7523 section 2.2).',
                $exception,
            );
        }
    }

    /**
     * Which client an assertion claims to come from, before anything of it is verified: its "sub" names
     * the client (RFC 7523 §3), and the "client_id" of the body names it too when the client sends both.
     * Whether the two agree is judged once the signature has been.
     *
     * @throws ClientAuthenticationFailure when neither names a client, and there is nothing to look up
     */
    public function assertedClientId(UnverifiedJwt $assertion): string
    {
        $clientId = $assertion->claim('sub') ?? $this->clientId();
        if ($clientId === null) {
            throw ClientAuthenticationFailure::refused(
                ClientAuthenticationFailureReason::InvalidAssertion,
                null,
                null,
                'the client assertion names no client in its "sub"',
            );
        }

        return $clientId;
    }
}
