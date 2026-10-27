<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;

/**
 * The shape a client registered for one document (ResponseFormat), addressed: with what the document needs from
 * outside the provider. That is the key of the tenant its JWS is signed with when the shape signs it, opened by the
 * KMS, and the key of the client its JWE goes to when the shape encrypts it (OIDC Core §3.1.3.7, RFC 7516 §7.1), read
 * back from what the client publishes. Both are read before the document is struck and travel with the shape: whoever
 * spends something on the way to a document reads them first, and striking the document then depends on nothing the
 * KMS or the client serves.
 */
final readonly class AddressedFormat
{
    /**
     * @param OpenedSigningKeyInterface|null $signingKey the key of the tenant the JWS is signed with, opened, null for a shape that signs nothing
     * @param array<string, mixed>|null $recipient the public JWK of the client the JWE is addressed to, null for a shape that encrypts nothing
     *
     * @throws InvalidArgumentException when a shape that signs is given no key to sign with, or a shape that does not is given one,
     *                                  and when a shape that encrypts is given no key of the client, or a shape that does not is given one
     */
    public function __construct(
        public ResponseFormat $format,
        private ?OpenedSigningKeyInterface $signingKey = null,
        private ?array $recipient = null,
    ) {
        if ($format->isSigned !== ($signingKey !== null)) {
            throw new InvalidArgumentException('A document is signed with one key of the tenant when its shape signs it, and with none when it does not.');
        }
        if ($format->isEncrypted() !== ($recipient !== null)) {
            throw new InvalidArgumentException('A document is addressed to one key of the client when its shape encrypts it, and to none when it does not.');
        }
    }

    /**
     * @throws LogicException when the shape signs nothing, so that no key of the tenant was opened for the document
     *
     * @return OpenedSigningKeyInterface the key of the tenant the JWS is signed with, opened
     */
    public function signingKey(): OpenedSigningKeyInterface
    {
        return $this->signingKey ?? throw new LogicException('A document whose shape signs nothing is signed with no key.');
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
