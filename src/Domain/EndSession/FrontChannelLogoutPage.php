<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\EndSession;

use function array_unique;
use function array_values;
use Heidi\Oidc\Domain\Page\InlineScript;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function implode;
use function sort;
use function sprintf;

/**
 * Front-Channel Logout 1.0 §2 and §3: the page the provider renders once a session has ended, one iframe
 * per client that registered a front-channel logout URI, loaded by the browser that holds the cookies of
 * those clients. What the page is made of is fixed here, in the module, because the
 * Content-Security-Policy is part of the answer: the frames it names are the registered URIs and nothing
 * else, and the one script that moves the browser on is named by its hash.
 *
 * What this page cannot promise is not worked around: an iframe of another origin reaches its relying
 * party only if the browser sends that party's cookies, and a browser that blocks third-party cookies
 * does not. The provider says it asked; it does not say the user is signed out everywhere. Back-Channel
 * Logout 1.0 (§4.9) is what does not depend on a browser.
 */
final readonly class FrontChannelLogoutPage
{
    /**
     * Moves the browser on once every frame has loaded or failed, and at the latest after the wait below,
     * because a logout page has to end even when a relying party never answers. Its text is a constant
     * because the hash of the policy is computed from it: change one byte here and the page stops running
     * its own script.
     */
    public const string SCRIPT = 'var g=function(){location.replace(document.links[0].href)},f=document.getElementsByTagName("iframe"),n=f.length,d=function(){--n<=0&&g()},i;for(i=0;i<f.length;i++){f[i].onload=d;f[i].onerror=d}setTimeout(g,3000);';

    /**
     * Seconds the page waits for the slowest relying party before moving on, the same number the script
     * holds: long enough for a frame on a warm connection, short enough that a logout ends.
     */
    public const int WAIT = 3;

    /**
     * @var non-empty-list<string> the URIs of the frames, in the order the clients signed in
     */
    public array $frames;

    /**
     * @var non-empty-list<string> the origins the frames are on, for the policy (RFC 6454 §3.2), each
     *                             once and in the same order whatever order the clients signed in, so
     *                             that one set of clients is one policy
     */
    public array $origins;

    /**
     * @param list<FrontChannelLogoutFrame> $frames at least one; a page with no frame is not rendered
     * @param string|null $continueTo where the browser goes once the frames are done, the
     *                                post_logout_redirect_uri of the request when it named one
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
     * CSP Level 3 §6.6.2.2 "hash-source", over the text of the script element.
     */
    public function scriptHash(): string
    {
        return new InlineScript(self::SCRIPT)->cspHashSource();
    }

    /**
     * Nothing loads but the frames the clients registered, nothing frames this page, and the one script
     * is named by its hash rather than inline scripts allowed at large (CSP Level 3 §6.1, §6.3.2). The
     * script is only needed when there is somewhere to continue to.
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
