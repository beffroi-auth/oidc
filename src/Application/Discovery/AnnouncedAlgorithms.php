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

/**
 * How the document names the algorithms of the provider. Every member that lists algorithms says the
 * same thing about the same wiring, so it is said here once and the contributors that announce one read
 * it: what signs a JWS, what a client encrypts to, and what a client assertion may be signed with.
 */
final readonly class AnnouncedAlgorithms
{
    public function __construct(
        private SignatureAlgorithmsInterface $signature,
        private KeyEncryptionAlgorithmsInterface $keyEncryption,
        private ContentEncryptionAlgorithmsInterface $contentEncryption,
    ) {
    }

    /**
     * What the provider signs a JWS with, whichever a client registered: an ID token, a UserInfo answer,
     * a signed authorization response, and what it verifies a DPoP proof with, which a challenge under
     * DPoP names too (RFC 9449 §7.1).
     *
     * @return non-empty-list<string>
     */
    public function signing(): array
    {
        return AlgorithmNames::of($this->signature->all());
    }

    /**
     * What the provider signs a JWS with where no client registers a choice: a signed introspection
     * response, whose algorithm the provider determines (RFC 9701 §6). The one it signs with, and not
     * every one it could.
     *
     * @return non-empty-list<string>
     */
    public function defaultSigning(): array
    {
        return AlgorithmNames::of([$this->signature->defaultAlgorithm()]);
    }

    /**
     * The pair of members that says what a document may be encrypted with, named after the document
     * (OIDC Discovery §3). A provider nobody encrypts to announces neither, rather than two empty lists:
     * there is nothing to encrypt with, which is not the same as encrypting with nothing. It takes both
     * halves to encrypt anything, so half a wiring announces nothing either.
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
     * What an assertion of those methods may be signed with, each algorithm once: the methods say it,
     * nothing enumerates it here.
     *
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
