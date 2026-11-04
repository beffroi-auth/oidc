<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;

/**
 * OIDC Registration §2
 *
 * Signed, then encrypted, never the other way round.
 */
final readonly class ResponseFormat
{
    private function __construct(
        public bool $isSigned,
        public ?SignatureAlgorithmInterface $signature,
        public ?ResponseEncryption $encryption,
    ) {
    }

    /**
     * @param SignatureAlgorithmInterface|null $signature null for the algorithm the provider signs with
     */
    public static function signed(?SignatureAlgorithmInterface $signature = null, ?ResponseEncryption $encryption = null): self
    {
        return new self(true, $signature, $encryption);
    }

    public static function unsigned(?ResponseEncryption $encryption = null): self
    {
        return new self(false, null, $encryption);
    }

    public function isEncrypted(): bool
    {
        return $this->encryption !== null;
    }

    /**
     * Neither signed nor encrypted.
     */
    public function isPlain(): bool
    {
        return ! $this->isSigned && $this->encryption === null;
    }
}
