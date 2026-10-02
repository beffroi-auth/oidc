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
 * "private_key_jwt" (OIDC Core §9, RFC 7523 §2.2): the client signs a JWT with a key of its own and the
 * provider verifies it against the keys the client publishes. One of the two ways FAPI 2.0 §5.2.2
 * accepts, and the only one that needs no secret at rest on either side.
 *
 * What an assertion may be signed with is what the provider is wired with (issue #156): a deployment
 * that follows FAPI 2 drops the RS256 line of its wiring and the method refuses RS256 with it, the
 * discovery document saying so in "token_endpoint_auth_signing_alg_values_supported".
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
