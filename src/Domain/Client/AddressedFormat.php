<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Key\OpenedSigningKeyInterface;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;

/**
 * A ResponseFormat with the keys its document needs, opened and read before anything is spent.
 */
final readonly class AddressedFormat
{
    /**
     * @param array<string, mixed>|null $recipient the public JWK of the client
     *
     * @throws InvalidArgumentException when a key the shape needs is missing, or one it does not need is given
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
     * @throws LogicException when the shape signs nothing
     */
    public function signingKey(): OpenedSigningKeyInterface
    {
        return $this->signingKey ?? throw new LogicException('A document whose shape signs nothing is signed with no key.');
    }

    /**
     * @throws LogicException when the shape encrypts nothing
     *
     * @return array<string, mixed> the public JWK of the client
     */
    public function recipient(): array
    {
        return $this->recipient ?? throw new LogicException('A document whose shape encrypts nothing is addressed to no key.');
    }
}
