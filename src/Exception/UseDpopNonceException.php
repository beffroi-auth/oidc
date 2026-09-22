<?php

declare(strict_types=1);

namespace Heidi\Oidc\Exception;

use Heidi\Oidc\Domain\Token\KeyConfirmation;

/**
 * RFC 9449 §8 "use_dpop_nonce": the provider asks the client to make its proof again, with the nonce
 * handed back beside this refusal. The nonce is the whole of what the client has to keep, and only
 * until its next request; whoever replays a proof made before it was issued is refused by it.
 */
final class UseDpopNonceException extends OAuth2Exception implements ChallengeInterface
{
    /**
     * RFC 9449 §8: the header the fresh nonce is handed back in, at an endpoint that issues tokens as
     * at a resource that honours one.
     */
    public const string HEADER = 'DPoP-Nonce';

    /**
     * @param string $nonce the fresh nonce, answered in the DPoP-Nonce header of RFC 9449 §8
     */
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
