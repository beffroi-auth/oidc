<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;

/**
 * The shape a client registered for one kind of document the provider hands it (OIDC Registration §2):
 * the ID token (OIDC Core §3.1.3.7), the UserInfo answer (§5.3.2) and the signed authorization response
 * (JARM §2.1). Signed, then encrypted, in that order and never the other way round: what proves who wrote
 * the document is inside what hides it.
 *
 * A document that is always signed says so with signed(), and a null algorithm there means the one the
 * provider signs with, a client being free to register none. A UserInfo answer is the one document a
 * client may receive unsigned, and unsigned() says it: encrypted alone, its payload is the plain JSON of
 * §5.3.2, and encrypted by nothing it is that JSON.
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
     * @param SignatureAlgorithmInterface|null $signature what the client registered, null for the algorithm the provider signs with
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
     * Neither signed nor encrypted: the document travels as it is written.
     */
    public function isPlain(): bool
    {
        return ! $this->isSigned && $this->encryption === null;
    }
}
