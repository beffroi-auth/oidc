<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Core\Port\JwsSignerInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ResponseEncryption;
use Heidi\Oidc\Domain\Client\ResponseFormat;
use Heidi\Oidc\Domain\Token\JwtPayload;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Port\JweEncrypterInterface;
use function sprintf;

/**
 * A document the provider hands one client, in the shape that client registered (OIDC Registration §2):
 * signed with the active key of the tenant, then wrapped in a JWE addressed to a key the client
 * publishes. Written once for the three documents that travel this way, the ID token (OIDC Core
 * §3.1.3.7), the UserInfo answer (§5.3.2) and the signed authorization response (JARM §2.1): what changes
 * between them is the claims and the registration they read, never the order of the two operations.
 *
 * Signed then encrypted, and never the other way round (OIDC Core §16.14): the signature says who wrote
 * the document and it travels inside what hides it, so that a client that opens a JWE finds something to
 * verify rather than something to trust. A nested JWT says so in its "cty" (RFC 7519 §5.2).
 */
final readonly class ClientDocumentIssuer
{
    /**
     * RFC 7519 §5.2: what the payload of a JWE is when it is itself a JWT.
     */
    private const string NESTED = 'JWT';

    public function __construct(
        private JwsSignerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
        private ClientKeySetProvider $keys,
        private JweEncrypterInterface $encrypter,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @throws LogicException when the format asks for neither a signature nor an encryption, which is a
     *                        document the caller hands over as it is and never here
     * @throws ClientKeysUnavailableException when the client publishes no key a JWE can be addressed to
     *
     * @return string the compact JWS, the compact JWE, or the JWS inside the JWE
     */
    public function issue(Client $client, ResponseFormat $format, array $claims): string
    {
        if ($format->isPlain()) {
            throw new LogicException(sprintf(
                'The client "%s" registered neither a signature nor an encryption for this document; it is handed over as it is.',
                $client->clientId,
            ));
        }
        $payload = JwtPayload::encode($claims);
        $header = [];
        if ($format->isSigned) {
            $payload = $this->signer->sign($client->tenant, $format->signature ?? $this->algorithms->defaultAlgorithm(), $payload);
            $header = [
                'cty' => self::NESTED,
            ];
        }
        $encryption = $format->encryption;
        if ($encryption === null) {
            return $payload;
        }

        return $this->encrypter->encrypt($this->recipient($client, $encryption), $encryption, $payload, $header);
    }

    /**
     * The key of the client the JWE is addressed to. A registration is checked when it is read, so a
     * client whose published set holds nothing usable is a client that changed its keys since: it is said
     * plainly, with the client and the algorithm, and no document leaves.
     *
     * @throws ClientKeysUnavailableException
     *
     * @return array<string, mixed>
     */
    private function recipient(Client $client, ResponseEncryption $encryption): array
    {
        return (
            $this->keys->keysOf($client, null)->encryptionKeyFor($encryption->algorithm) ?? throw new ClientKeysUnavailableException(sprintf(
                'The client "%s" publishes no key a document encrypted under "%s" can be addressed to.',
                $client->clientId,
                $encryption->algorithm->name(),
            ))
        );
    }
}
