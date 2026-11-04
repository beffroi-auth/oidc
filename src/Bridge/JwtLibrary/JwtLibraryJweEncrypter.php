<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Oidc\Domain\Client\ResponseEncryption;
use Beffroi\Oidc\Exception\RuntimeException;
use Beffroi\Oidc\Port\JweEncrypterInterface;
use function is_string;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use function sprintf;
use Throwable;

final readonly class JwtLibraryJweEncrypter implements JweEncrypterInterface
{
    private JWEBuilder $builder;

    private CompactSerializer $serializer;

    public function __construct(AlgorithmManager $algorithms)
    {
        $this->builder = new JWEBuilder($algorithms);
        $this->serializer = new CompactSerializer();
    }

    public function encrypt(array $recipient, ResponseEncryption $encryption, string $payload, array $protectedHeader = []): string
    {
        $keyId = $recipient['kid'] ?? null;
        $header = [
            ...$protectedHeader,
            'alg' => $encryption->algorithm->name(),
            'enc' => $encryption->method->name(),
        ];
        if (is_string($keyId) && $keyId !== '') {
            $header['kid'] = $keyId;
        }

        try {
            $jwe = $this->builder
                ->create()
                ->withPayload($payload)
                ->withSharedProtectedHeader($header)
                ->addRecipient(new JWK($recipient))
                ->build();

            return $this->serializer->serialize($jwe, 0);
        } catch (Throwable $exception) {
            throw new RuntimeException(
                sprintf('The document could not be encrypted under "%s": the key it is addressed to does not receive one.', $encryption->algorithm->name()),
                0,
                $exception,
            );
        }
    }
}
