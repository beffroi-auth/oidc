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
 * OIDC Registration §2, OIDC Core §16.14
 *
 * address() needs the KMS and the client's keys: done before a grant is spent, a failure costs the client nothing.
 */
final readonly class ClientDocumentIssuer
{
    /**
     * RFC 7519 §5.2
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
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     * @throws ClientKeysUnavailableException when the client's set cannot be read or holds no usable key
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
     * @param array<string, mixed> $signatureHeader the members of the JWS header besides "alg" and "kid"
     * @param array<string, mixed> $encryptionHeader the members of the JWE header besides "alg", "enc", "kid" and "cty"
     *
     * @throws LogicException when the shape neither signs nor encrypts
     * @throws ClientKeysUnavailableException when the key the document is addressed to receives no JWE
     */
    public function issue(Client $client, AddressedFormat $addressed, array $claims, array $signatureHeader = [], array $encryptionHeader = []): string
    {
        $format = $addressed->format;
        if ($format->isPlain()) {
            throw new LogicException(sprintf(
                'The client "%s" registered neither a signature nor an encryption for this document; it is handed over as it is.',
                $client->registration->clientId,
            ));
        }
        $payload = JwtPayload::encode($claims);
        if ($format->isSigned) {
            $payload = $addressed->signingKey()->sign($payload, $signatureHeader);
            $encryptionHeader['cty'] = self::NESTED;
        }
        $encryption = $format->encryption;
        if ($encryption === null) {
            return $payload;
        }

        return $this->encrypter->encrypt($addressed->recipient(), $encryption, $payload, $encryptionHeader);
    }
}
