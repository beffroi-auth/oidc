<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Discovery;

use function array_merge;
use function array_unique;
use function array_values;
use Beffroi\Core\Port\ContentEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\KeyEncryptionAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Client\AssertionMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;

final readonly class AnnouncedAlgorithms
{
    public function __construct(
        private SignatureAlgorithmsInterface $signature,
        private KeyEncryptionAlgorithmsInterface $keyEncryption,
        private ContentEncryptionAlgorithmsInterface $contentEncryption,
    ) {
    }

    /**
     * @return non-empty-list<string>
     */
    public function signing(): array
    {
        return AlgorithmNames::of($this->signature->all());
    }

    /**
     * @return non-empty-list<string>
     */
    public function defaultSigning(): array
    {
        return AlgorithmNames::of([$this->signature->defaultAlgorithm()]);
    }

    /**
     * Empty unless both halves are wired: two empty lists would announce encrypting with nothing.
     *
     * @return array<string, list<string>>
     */
    public function encryptionOf(string $member): array
    {
        $keys = $this->keyEncryption->all();
        $contents = $this->contentEncryption->all();
        if ($keys === [] || $contents === []) {
            return [];
        }

        return [
            $member . '_alg_values_supported' => AlgorithmNames::of($keys),
            $member . '_enc_values_supported' => AlgorithmNames::of($contents),
        ];
    }

    /**
     * @param list<ClientAuthenticationMethodInterface> $methods
     *
     * @return list<string>
     */
    public function assertionSigning(array $methods): array
    {
        $algorithms = [];
        foreach ($methods as $method) {
            if ($method instanceof AssertionMethodInterface) {
                $algorithms = array_merge($algorithms, $method->assertionSigningAlgorithms());
            }
        }

        return array_values(array_unique($algorithms));
    }
}
