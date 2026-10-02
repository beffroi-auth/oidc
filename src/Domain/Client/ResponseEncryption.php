<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use Beffroi\Core\Domain\Key\ContentEncryptionAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyEncryptionAlgorithmInterface;

/**
 * What a client registered to have a document encrypted with (OIDC Registration §2, JARM §3): the "alg"
 * that wraps, or agrees on, the content encryption key, and the "enc" that encrypts the payload. The two
 * always travel together, an "alg" encrypting nothing by itself, which is why they are one object and not
 * two registrations a deployment could leave half filled.
 */
final readonly class ResponseEncryption
{
    public function __construct(
        public KeyEncryptionAlgorithmInterface $algorithm,
        public ContentEncryptionAlgorithmInterface $method,
    ) {
    }
}
