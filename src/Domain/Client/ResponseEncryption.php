<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Key\ContentEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyEncryptionAlgorithmInterface;

/**
 * OIDC Registration §2, JARM §3
 */
final readonly class ResponseEncryption
{
    public function __construct(
        public KeyEncryptionAlgorithmInterface $algorithm,
        public ContentEncryptionAlgorithmInterface $method,
    ) {
    }
}
