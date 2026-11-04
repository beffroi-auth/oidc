<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Dpop;

use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use function implode;
use Beffroi\Oidc\Port\ChallengeParametersInterface;

/**
 * RFC 9449 §7.1
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
                'algs' => implode(' ', $this->algorithms->signing()),
            ],
        ];
    }
}
