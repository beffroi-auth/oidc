<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\JwtLibrary;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Port\ClientAssertionSecretVerifierInterface;
use function in_array;
use Jose\Component\Core\AlgorithmManager;
use function sprintf;

/**
 * OIDC Core §9, RFC 7518 §6.4
 */
final readonly class JwtLibraryClientAssertionSecretVerifier implements ClientAssertionSecretVerifierInterface
{
    private JwtLibrarySignature $signature;

    public function __construct(AlgorithmManager $algorithms)
    {
        $this->signature = new JwtLibrarySignature($algorithms);
    }

    public function verify(UnverifiedJwt $assertion, SharedClientSecret $secret, array $algorithms): void
    {
        $alg = $assertion->algorithm();
        if ($alg === null || ! in_array($alg, $algorithms, true)) {
            throw new InvalidJwtException(sprintf('The client assertion is signed with "%s", which this method does not take.', $alg ?? '?'));
        }
        $key = [
            'kty' => 'oct',
            'k' => Base64Url::encode($secret->value),
        ];
        if (! $this->signature->holdsUnder($assertion, $key)) {
            throw new InvalidJwtException('The MAC of the client assertion does not verify against the secret of the client.');
        }
    }
}
