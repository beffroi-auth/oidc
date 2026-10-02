<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function base64_decode;
use function hash;
use function hash_equals;
use Beffroi\Oidc\Domain\Token\Base64Url;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function preg_replace;
use function sprintf;
use function strlen;

/**
 * The certificate a client presented at the TLS handshake, as it reached the provider: the leaf in its
 * DER form and nothing else. The chain is not part of it, because no edge this application knows hands
 * one over (architecture §6); whatever has to be validated against a certificate authority is
 * validated where the handshake happens, not here (RFC 8705 §2.1).
 *
 * Nothing here reads what is inside the certificate. What names the client in it is read by a
 * CertificateReaderInterface, and the thumbprint below is the whole of what binding a token needs.
 */
final readonly class ClientCertificate
{
    /**
     * The one shape an edge hands a certificate over in, an envelope of RFC 7468 §5.
     */
    private const string PEM = '/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s';

    private function __construct(
        /**
         * The certificate as the handshake carried it, ASN.1 DER, which is what RFC 8705 §3.1 hashes.
         */
        public string $der,
    ) {
    }

    /**
     * The value the edge hands over. A listener that asks for a certificate without requiring one fills
     * the envelope when the client presented one and leaves it empty when it did not, so an empty
     * envelope is "this request was made without a certificate" and not a failure.
     *
     * @throws InvalidArgumentException when the value is not a PEM envelope, or carries something that
     *                                  is not base64: the edge is then misconfigured, and a provider
     *                                  that guessed here would bind a token to bytes nobody chose
     */
    public static function fromPem(string $pem): ?self
    {
        if (preg_match(self::PEM, $pem, $envelope) !== 1) {
            throw new InvalidArgumentException(sprintf('The edge handed over %d bytes that are not a PEM certificate envelope.', strlen($pem)));
        }
        $body = (string) preg_replace('/\s+/', '', $envelope[1]);
        if ($body === '') {
            return null;
        }
        $certificate = self::fromBase64($body);
        if ($certificate === null) {
            throw new InvalidArgumentException('The edge handed over a PEM certificate envelope whose contents are not base64.');
        }

        return $certificate;
    }

    /**
     * A certificate as a JWK Set carries one, base64 of the DER encoding and not base64url (RFC 7517
     * §4.7). What a client publishes is read as it is given: a value that is not base64 is not a
     * certificate, it names no client, and it is worth no exception.
     */
    public static function fromBase64(string $base64): ?self
    {
        $der = base64_decode($base64, true);
        if ($der === false || $der === '') {
            return null;
        }

        return new self($der);
    }

    /**
     * RFC 8705 §3.1: the SHA-256 thumbprint of the DER encoding, base64url without padding, which is
     * what a certificate-bound token names in "cnf" and what a resource server recomputes.
     */
    public function x5tS256(): string
    {
        return Base64Url::encode(hash('sha256', $this->der, true));
    }

    /**
     * Two certificates are the same certificate when their DER encodings are, compared through the
     * thumbprint both sides of a binding already speak in.
     */
    public function isSameAs(self $other): bool
    {
        return hash_equals($this->x5tS256(), $other->x5tS256());
    }
}
