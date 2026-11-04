<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Secret;

use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Core\Domain\Encoding\Base64Url;

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
