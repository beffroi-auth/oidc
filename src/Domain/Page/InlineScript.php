<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Page;

use function base64_encode;
use function hash;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * CSP Level 3 §6.6.2.2
 */
final readonly class InlineScript
{
    public function __construct(
        public string $text,
    ) {
        if ($text === '') {
            throw new InvalidArgumentException('An inline script named by its hash has a text to hash.');
        }
    }

    public function cspHashSource(): string
    {
        return 'sha256-' . base64_encode(hash('sha256', $this->text, true));
    }
}
