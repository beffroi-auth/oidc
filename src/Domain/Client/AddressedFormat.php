<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;

/**
 * The shape a client registered for one document (ResponseFormat), addressed: with the key of the client its
 * JWE goes to when the shape encrypts it (OIDC Core §3.1.3.7, RFC 7516 §7.1). That key is the one thing a
 * document needs from outside the provider, read back from what the client publishes, so it is read before
 * the document is struck and travels with the shape: whoever spends something on the way to a document
 * reads it first, and striking the document then depends on nothing the client serves.
 */
final readonly class AddressedFormat
{
    /**
     * @param array<string, mixed>|null $recipient the public JWK of the client the JWE is addressed to, null for a shape that encrypts nothing
     *
     * @throws InvalidArgumentException when a shape that encrypts is given no key, or a shape that does not is given one
     */
    public function __construct(
        public ResponseFormat $format,
        private ?array $recipient = null,
    ) {
        if ($format->isEncrypted() !== ($recipient !== null)) {
            throw new InvalidArgumentException('A document is addressed to one key of the client when its shape encrypts it, and to none when it does not.');
        }
    }

    /**
     * @throws LogicException when the shape encrypts nothing, so that the document goes to no key
     *
     * @return array<string, mixed> the public JWK of the client the JWE is addressed to
     */
    public function recipient(): array
    {
        return $this->recipient ?? throw new LogicException('A document whose shape encrypts nothing is addressed to no key.');
    }
}
