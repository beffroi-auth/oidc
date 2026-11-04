<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Certificate;

use function base64_decode;
use function hash;
use function hash_equals;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function preg_match;
use function preg_replace;
use function sprintf;
use function strlen;

/**
 * The leaf only: the edge judges its chain, validity and revocation at the handshake (RFC 8705 §2.1).
 */
final readonly class ClientCertificate
{
    /**
     * RFC 7468 §5
     */
    private const string PEM = '/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s';

    private function __construct(
        public string $der,
    ) {
    }

    /**
     * An empty envelope means no certificate: an edge that does not require one leaves it empty.
     *
     * @throws InvalidArgumentException when the value is not a PEM envelope of base64
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
     * RFC 7517 §4.7
     *
     * Base64, not base64url. A value that is not base64 names no client and gives null, never an exception.
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
     * RFC 8705 §3.1
     */
    public function x5tS256(): string
    {
        return Base64Url::encode(hash('sha256', $this->der, true));
    }

    public function isSameAs(self $other): bool
    {
        return hash_equals($this->x5tS256(), $other->x5tS256());
    }
}
