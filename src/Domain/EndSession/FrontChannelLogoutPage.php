<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\EndSession;

use function array_unique;
use function array_values;
use Beffroi\Oidc\Domain\Page\InlineScript;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function sort;
use function sprintf;

/**
 * Front-Channel Logout 1.0 §2, §3
 */
final readonly class FrontChannelLogoutPage
{
    /**
     * Moves the browser on once every frame has loaded or failed, or after WAIT seconds at the latest. The policy
     * names it by the hash of this exact text.
     */
    public const string SCRIPT = 'var g=function(){location.replace(document.links[0].href)},f=document.getElementsByTagName("iframe"),n=f.length,d=function(){--n<=0&&g()},i;for(i=0;i<f.length;i++){f[i].onload=d;f[i].onerror=d}setTimeout(g,3000);';

    /**
     * Seconds, the same number SCRIPT holds in milliseconds.
     */
    public const int WAIT = 3;

    /**
     * @var non-empty-list<string>
     */
    public array $frames;

    /**
     * @var non-empty-list<string> each once and sorted, so that one set of clients is one policy
     */
    public array $origins;

    /**
     * @param list<FrontChannelLogoutFrame> $frames at least one
     */
    public function __construct(
        array $frames,
        public ?string $continueTo,
    ) {
        if ($frames === []) {
            throw new InvalidArgumentException('A front-channel logout page carries at least one frame (Front-Channel Logout 1.0 section 2).');
        }
        $uris = [];
        $origins = [];
        foreach ($frames as $frame) {
            $uris[] = $frame->uri;
            $origins[] = $frame->origin;
        }
        $this->frames = $uris;
        $origins = array_values(array_unique($origins));
        sort($origins);
        $this->origins = $origins;
    }

    /**
     * CSP Level 3 §6.6.2.2
     */
    public function scriptHash(): string
    {
        return new InlineScript(self::SCRIPT)->cspHashSource();
    }

    /**
     * CSP Level 3 §6.1, §6.3.2
     */
    public function contentSecurityPolicy(): string
    {
        return sprintf(
            "default-src 'none'; frame-src %s; script-src %s; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            implode(' ', $this->origins),
            $this->continueTo === null ? "'none'" : sprintf("'%s'", $this->scriptHash()),
        );
    }
}
