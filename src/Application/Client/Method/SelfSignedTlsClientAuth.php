<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Method;

use Heidi\Oidc\Application\Client\ClientAuthenticationFailure;
use Heidi\Oidc\Application\Client\ClientAuthenticationRequest;
use Heidi\Oidc\Application\Client\ClientKeySetProvider;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Heidi\Oidc\Domain\Event\ClientAuthenticationFailureReason;
use Heidi\Oidc\Domain\Token\Confirmation;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\LogicException;
use function sprintf;

/**
 * "self_signed_tls_client_auth" (RFC 8705 §2.2): the client presents a certificate it signed itself, and
 * the provider authenticates it when that certificate is one of those the client publishes in its JWK
 * Set, in the "x5c" of a key (RFC 7517 §4.7) or by the thumbprint of §4.9.
 *
 * There is no chain and no trust store: what is trusted is what the client published, exactly as for the
 * keys of "private_key_jwt". The certificate itself is compared and not the key inside it, because a
 * certificate reissued on the same key is another certificate: §2.2 authenticates a certificate the
 * client registered, and §3.1 binds the tokens of that request to the thumbprint of that very one.
 *
 * A client that rotates its certificate publishes the new one before presenting it, which is the same
 * discipline a client that rotates a signing key follows; a set behind a "jwks_uri" is read back with
 * the guard time of ClientKeySetProvider.
 */
final readonly class SelfSignedTlsClientAuth implements KeyBearingMethodInterface, ConfirmingMethodInterface
{
    public function __construct(
        private ClientKeySetProvider $keys,
    ) {
    }

    public function name(): string
    {
        return 'self_signed_tls_client_auth';
    }

    public function mechanism(): string
    {
        return ClientAuthenticationRequest::CERTIFICATE;
    }

    public function authenticatesClient(): bool
    {
        return true;
    }

    public function presentedBy(ClientAuthenticationRequest $request): ?string
    {
        return $request->certificate === null ? null : $request->clientId();
    }

    public function verify(ClientAuthenticationRequest $request, Client $client): void
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            throw new LogicException(sprintf('The client "%s" is not authenticated by %s here.', $client->clientId, $this->name()));
        }
        try {
            $published = $this->keys->keysOf($client, null);
        } catch (ClientKeysUnavailableException $exception) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnreadableClientKeys, $client->clientId, $this->name(), $exception->getMessage(), $exception);
        }
        if (! $published->publishes($certificate)) {
            throw ClientAuthenticationFailure::refused(ClientAuthenticationFailureReason::UnexpectedCertificate, $client->clientId, $this->name(), 'the certificate presented is not one the client publishes');
        }
    }

    /**
     * A certificate is compared to what a client published, which is public on both sides: nothing here
     * is a secret whose comparison has to be made constant.
     */
    public function payRefusal(ClientAuthenticationRequest $request): void
    {
    }

    public function confirmationOf(ClientAuthenticationRequest $request): Confirmation
    {
        $certificate = $request->certificate;
        if ($certificate === null) {
            throw new LogicException(sprintf('A request that authenticated a client with %s carries a certificate.', $this->name()));
        }

        return Confirmation::ofCertificate($certificate);
    }
}
