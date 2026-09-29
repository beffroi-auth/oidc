<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use SensitiveParameter;

/**
 * What the provider is about to keep of a registration it has read: the members the client sent, the
 * members the policy of its tenant wrote on them (decision 0017), and the secret in the shape the
 * registered method verifies against.
 *
 * The drawn value is beside the shape and not in it, because it is the one thing that is answered and not
 * kept: the provider says it once, at the moment it assigns one (RFC 7591 §3.2.1), and a client that
 * already held the secret its method proves is handed nothing new.
 */
final readonly class KeptRegistration
{
    /**
     * @param array<string, mixed> $metadata the members of RFC 7591 §2 the client sent, as it sent them
     * @param array<string, mixed> $assigned the members the registration policy of the tenant wrote
     * @param ClientSecretInterface|null $secret null for a client whose registered method proves none
     * @param string|null $drawnSecret the value the provider drew for this registration, to be answered once; null when it drew none
     */
    public function __construct(
        public array $metadata,
        public array $assigned,
        #[SensitiveParameter]
        public ?ClientSecretInterface $secret,
        #[SensitiveParameter]
        public ?string $drawnSecret = null,
    ) {
    }
}
