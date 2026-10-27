<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Port\SigningKeyOpenerInterface;
use Beffroi\Oidc\Domain\Client\AddressedFormat;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ResponseFormat;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Port\JweEncrypterInterface;
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
 *
 * **Addressed, then struck.** Two steps depend on something outside the provider answering right now: the key
 * of the tenant the JWS is signed with is opened by the KMS, and the key the JWE goes to is read back from what
 * the client publishes. address() does both, and issue() strikes the document for the shape it is handed
 * without asking anything of either. A caller that spends nothing on the way does both at once; the token
 * endpoint addresses the ID token before the grant spends what the request presented, so that a KMS that does
 * not answer and a set that cannot be read cost the client nothing.
 */
final readonly class ClientDocumentIssuer
{
    /**
     * RFC 7519 §5.2: what the payload of a JWE is when it is itself a JWT.
     */
    private const string NESTED = 'JWT';

    public function __construct(
        private SigningKeyOpenerInterface $signer,
        private SignatureAlgorithmsInterface $algorithms,
        private ClientKeySetProvider $keys,
        private JweEncrypterInterface $encrypter,
    ) {
    }

    /**
     * The shape, with the key of the tenant its JWS is signed with, opened, when it signs, and the key of the
     * client a JWE under its algorithm is addressed to when it encrypts. A registration is checked when it is
     * read, so a client whose published set holds nothing usable is a client that changed its keys since: it
     * is said plainly, with the client and the algorithm, and no document leaves.
     *
     * @throws KeyNotFoundException when the tenant has no active key for the algorithm the document is signed with
     * @throws KmsUnavailableException when the KMS does not answer to open that key, which is not open yet
     * @throws ClientKeysUnavailableException when the set the client publishes cannot be read, or holds no key a JWE under that algorithm can be addressed to
     */
    public function address(Client $client, ResponseFormat $format): AddressedFormat
    {
        $signingKey = $format->isSigned ? $this->signer->open($client->tenant, $format->signature ?? $this->algorithms->defaultAlgorithm()) : null;
        $encryption = $format->encryption;
        if ($encryption === null) {
            return new AddressedFormat($format, $signingKey);
        }

        return new AddressedFormat(
            $format,
            $signingKey,
            $this->keys->keysOf($client, null)->encryptionKeyFor($encryption->algorithm) ?? throw new ClientKeysUnavailableException(sprintf(
                'The client "%s" publishes no key a document encrypted under "%s" can be addressed to.',
                $client->registration->clientId,
                $encryption->algorithm->name(),
            )),
        );
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @throws LogicException when the shape asks for neither a signature nor an encryption, which is a
     *                        document the caller hands over as it is and never here
     *
     * @return string the compact JWS, the compact JWE, or the JWS inside the JWE
     */
    public function issue(Client $client, AddressedFormat $addressed, array $claims): string
    {
        $format = $addressed->format;
        if ($format->isPlain()) {
            throw new LogicException(sprintf(
                'The client "%s" registered neither a signature nor an encryption for this document; it is handed over as it is.',
                $client->registration->clientId,
            ));
        }
        $payload = JwtPayload::encode($claims);
        $header = [];
        if ($format->isSigned) {
            $payload = $addressed->signingKey()->sign($payload);
            $header = [
                'cty' => self::NESTED,
            ];
        }
        $encryption = $format->encryption;
        if ($encryption === null) {
            return $payload;
        }

        return $this->encrypter->encrypt($addressed->recipient(), $encryption, $payload, $header);
    }
}
