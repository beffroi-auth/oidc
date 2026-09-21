<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\ClientAssertion;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Exception\InvalidClientAssertionException;
use Heidi\Oidc\Port\ClientAssertionReaderInterface;
use function is_string;
use function sprintf;

/**
 * One request at an endpoint that authenticates a client (RFC 6749 §2.3): the header it carries, the
 * form parameters it carries, and the URL of the endpoint that received it, which an assertion may name
 * as its audience (RFC 7523 §3). The parameters a client authentication reads are checked to be strings
 * as soon as the request is built: a request whose credentials are not strings is refused before
 * anything is read, and the audit trail keeps no identifier from it, because none of it can be trusted.
 */
final class ClientAuthenticationRequest
{
    /**
     * RFC 6749 §2.3.1, RFC 7523 §2.2: the parameters a client authentication reads, all of them strings.
     */
    private const array CREDENTIAL_PARAMETERS = ['client_id', 'client_secret', 'client_assertion', 'client_assertion_type'];

    private bool $assertionRead = false;

    private ?ClientAssertion $assertion = null;

    /**
     * @param string $endpoint the absolute URL of the endpoint that received the request
     * @param array<string, mixed> $parameters the form parameters of the request body
     *
     * @throws ClientAuthenticationFailure when a credential parameter is present and is not a string
     */
    public function __construct(
        public readonly Tenant $tenant,
        public readonly string $endpoint,
        public readonly ?string $authorizationHeader,
        private readonly array $parameters,
        public readonly RequestContext $context,
    ) {
        foreach (self::CREDENTIAL_PARAMETERS as $name) {
            $value = $parameters[$name] ?? null;
            if ($value !== null && ! is_string($value)) {
                throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, null, null, sprintf('The %s parameter must be a string.', $name));
            }
        }
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
    public function assertion(ClientAssertionReaderInterface $reader): ?ClientAssertion
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
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, $this->clientId(), null, 'The client_assertion and client_assertion_type parameters go together (RFC 7523 section 2.2).');
        }
        if ($type !== ClientAssertion::TYPE) {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, $this->clientId(), null, sprintf('The client_assertion_type parameter must be "%s" (RFC 7523 section 2.2).', ClientAssertion::TYPE));
        }
        try {
            return $this->assertion = $reader->read($assertion);
        } catch (InvalidClientAssertionException $exception) {
            throw ClientAuthenticationFailure::malformedRequest(ClientAuthenticationFailureReason::MalformedCredentials, $this->clientId(), null, 'The client assertion is not a readable JWT (RFC 7523 section 2.2).', $exception);
        }
    }

    /**
     * Which client an assertion claims to come from, before anything of it is verified: its "sub" names
     * the client (RFC 7523 §3), and the "client_id" of the body names it too when the client sends both.
     * Whether the two agree is judged once the signature has been.
     *
     * @throws ClientAuthenticationFailure when neither names a client, and there is nothing to look up
     */
    public function assertedClientId(ClientAssertion $assertion): string
    {
        $clientId = $assertion->claim('sub') ?? $this->clientId();
        if ($clientId === null) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::InvalidAssertion, null, null, 'the client assertion names no client in its "sub"');
        }

        return $clientId;
    }
}
