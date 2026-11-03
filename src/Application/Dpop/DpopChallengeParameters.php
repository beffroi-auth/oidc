<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Dpop;

use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use function implode;
use Beffroi\Oidc\Port\ChallengeParametersInterface;

/**
 * RFC 9449 §7.1: a challenge under the DPoP scheme names, in "algs", the algorithms a proof may be signed
 * with, so that a client learns them where it is refused and not from the discovery document alone.
 *
 * They are the algorithms the provider is wired with: what it signs with, announces in
 * "dpop_signing_alg_values_supported" and verifies a proof with (`DpopProofVerifier`), never a list kept
 * beside them.
 */
final readonly class DpopChallengeParameters implements ChallengeParametersInterface
{
    public function __construct(
        private AnnouncedAlgorithms $algorithms,
    ) {
    }

    public function challengeParameters(): array
    {
        return [
            KeyConfirmation::SCHEME => [
                // a space-delimited list of JWS "alg" values (RFC 9449 §7.1, RFC 7515 §4.1.1)
                'algs' => implode(' ', $this->algorithms->signing()),
            ],
        ];
    }
}
