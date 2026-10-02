<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Page;

use function base64_encode;
use function hash;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The one script a page of this provider runs, named by its hash so that the page can refuse every other
 * script instead of allowing inline scripts at large (CSP Level 3 §6.6.2.2 "hash-source").
 *
 * The text is what the hash is computed from, so the two cannot drift: a page carries the script and
 * asks it for the source its policy names. Every page the provider renders that runs a script does it
 * this way, and none of them writes the hashing again.
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

    /**
     * The "hash-source" a Content-Security-Policy names this script by (CSP Level 3 §6.6.2.2), over the
     * text of the script element.
     */
    public function cspHashSource(): string
    {
        return 'sha256-' . base64_encode(hash('sha256', $this->text, true));
    }
}
