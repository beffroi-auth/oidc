<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Dpop;

use DateTimeImmutable;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Oidc\Application\Key\AlgorithmNames;
use Beffroi\Oidc\Domain\Dpop\DpopProof;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\InvalidDpopProofException;
use Beffroi\Oidc\Exception\InvalidJwtException;
use Beffroi\Oidc\Exception\UseDpopNonceException;
use Beffroi\Oidc\Port\CompactJwtReaderInterface;
use Beffroi\Oidc\Port\ProofKeyVerifierInterface;
use SensitiveParameter;

/**
 * RFC 9449 §4
 */
final readonly class DpopProofVerifier
{
    public function __construct(
        private CompactJwtReaderInterface $jwts,
        private ProofKeyVerifierInterface $keys,
        private DpopProofValidator $validator,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    /**
     * @param string $url the URL this provider publishes for the endpoint that received it
     *
     * @throws InvalidDpopProofException
     * @throws UseDpopNonceException
     */
    public function verify(
        ?string $proof,
        string $method,
        string $url,
        DateTimeImmutable $now,
        #[SensitiveParameter]
        ?string $accessToken = null,
    ): ?KeyConfirmation {
        if ($proof === null || $proof === '') {
            return null;
        }
        try {
            $jwt = $this->jwts->read($proof);
        } catch (InvalidJwtException $exception) {
            throw new InvalidDpopProofException('The DPoP proof is not a readable JWT (RFC 9449 section 4.2).', $exception);
        }
        try {
            $key = new KeyConfirmation($this->keys->keyThatSigned($jwt, $this->names()));
        } catch (InvalidJwtException|InvalidArgumentException $exception) {
            throw new InvalidDpopProofException('The DPoP proof is not signed by the key it carries (RFC 9449 section 4.3).', $exception);
        }
        $this->validator->validate(new DpopProof($jwt), $key, $method, $url, $accessToken, $now);

        return $key;
    }

    /**
     * @return list<string>
     */
    private function names(): array
    {
        return AlgorithmNames::of($this->algorithms->all());
    }
}
