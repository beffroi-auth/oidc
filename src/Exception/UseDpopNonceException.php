<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use Beffroi\Oidc\Domain\Token\KeyConfirmation;

/**
 * RFC 9449 §8
 */
final class UseDpopNonceException extends OAuth2Exception implements ChallengeInterface
{
    /**
     * RFC 9449 §8
     */
    public const string HEADER = 'DPoP-Nonce';

    public function __construct(
        public readonly string $nonce,
        string $description,
    ) {
        parent::__construct('use_dpop_nonce', $description, 400, false);
    }

    public function challengeScheme(): string
    {
        return KeyConfirmation::SCHEME;
    }

    public function challengeHeaders(): array
    {
        return [
            self::HEADER => $this->nonce,
        ];
    }
}
