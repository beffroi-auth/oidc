<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Method;

use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Client\ClientAssertionValidator;
use Beffroi\Oidc\Application\Client\ClientKeySetProvider;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\KeyBearingMethodInterface;
use Beffroi\Oidc\Domain\Token\UnverifiedJwt;
use Beffroi\Oidc\Port\JwtKeyVerifierInterface;

/**
 * OIDC Core §9, RFC 7523 §2.2
 */
final readonly class PrivateKeyJwt extends AssertionMethod implements KeyBearingMethodInterface
{
    public function __construct(
        private JwtKeyVerifierInterface $verifier,
        private ClientKeySetProvider $keys,
        ClientAssertionValidator $claims,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
        parent::__construct($claims);
    }

    public function name(): string
    {
        return 'private_key_jwt';
    }

    public function assertionSigningAlgorithms(): array
    {
        return AlgorithmNames::of($this->algorithms->all());
    }

    protected function verifySignature(UnverifiedJwt $assertion, Client $client): void
    {
        $this->verifier->verify($assertion, $this->keys->keysAuthenticating($client, $assertion->keyId(), $this), $this->assertionSigningAlgorithms());
    }
}
