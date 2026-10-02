<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Secret;

use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\Base64Url;

/**
 * Draws the values this provider hands out and recognises again later: an authorization code, a refresh
 * token, an opaque access token, the reference a pushed request answers with, the identifier of an
 * interaction. All of them are the same value, drawn in one place and in one way, of the shape DrawnSecret
 * describes; where a record keeps one, it keeps the digest and never the value.
 *
 * It is given its randomness as a use case is given its clock (RandomnessInterface): a test fixes what a
 * value will be and reads it back, and a deployment that needs its own source provides one.
 */
final readonly class SecretDrawer
{
    public function __construct(
        private RandomnessInterface $randomness,
    ) {
    }

    public function draw(): string
    {
        return Base64Url::encode($this->randomness->bytes(DrawnSecret::LENGTH));
    }
}
