<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientUri;
use function implode;
use function sprintf;

/**
 * What the consent page shows of the client that is asking (OIDC Registration §2): the logo, the pages
 * the user may read before deciding, and the Content-Security-Policy that goes with them. The name is
 * shown whatever the client registered, so it is read from the presentation and needs nothing here.
 *
 * What the page is made of is fixed in the module, because the policy is part of the answer, as it is
 * for the two pages that carry a step of the protocol (FormPostResponse, FrontChannelLogoutPage). Here
 * what it is part of is what a stranger costs: the image is served by a host the client named, so the
 * browser of the user fetches it and that host learns the address of the user and the moment the page
 * was shown, whether or not consent follows. That is the price of showing a logo at all, and it is
 * bounded rather than removed: the policy names the origin of that one image and no other, so nothing a
 * client registers makes the page load anything else.
 *
 * The provider fetches none of it. A logo read and cached here would be an outbound request on a URL a
 * client wrote, which is what the "sector_identifier_uri" and the "jwks_uri" rules bound so carefully
 * and what decision 0006 does not spend on a picture. The page names the URL; the browser loads it or
 * does not, and the provider learns nothing either way.
 *
 * Unlike those two pages, this one is a page of the product: it extends the layout an application
 * overrides (architecture §5.2), so the policy says what may be loaded on the client's behalf and leaves
 * the rest to the application, where "default-src 'none'" would block the stylesheet that gives every
 * page of the deployment its look.
 */
final readonly class ConsentPage
{
    /**
     * @var array<non-empty-string, ClientUri> the pages of the client the user may open before deciding,
     *                                         under the name of the member that registered each (OIDC
     *                                         Registration §2), in the order the page shows them: what
     *                                         the client does with the data first, what it asks of the
     *                                         user next, and who it is last. A member the client
     *                                         registered nothing for is absent rather than empty
     */
    public array $links;

    /**
     * @param TenantLook $look what the tenant shows of itself on every page of its provider (issue #449);
     *                         its logo is on this one too, so the policy names where that one is served
     *                         from as well
     */
    public function __construct(
        public ClientPresentation $presentation,
        public TenantLook $look = new TenantLook(),
    ) {
        $links = [];
        foreach ([
            'policy_uri' => $presentation->policyUri,
            'tos_uri' => $presentation->tosUri,
            'client_uri' => $presentation->uri,
        ] as $member => $uri) {
            if ($uri !== null) {
                $links[$member] = $uri;
            }
        }
        $this->links = $links;
    }

    /**
     * CSP Level 3 §6.1, §6.3.2: the page loads the logo of this client and no other image, and nothing
     * frames it (RFC 9700 §4.15). The origin is what a source expression names (RFC 6454 §3.2), never
     * the URL, and the provider's own origin is there for the images a deployment puts in its layout.
     *
     * A client that registered no logo, for a tenant that declared none either, leaves a policy that
     * names no origin at all, which is the page a deployment that declares its clients itself has always
     * served.
     *
     * The links are not in it and cannot be: a Content-Security-Policy says what a page loads, and a
     * link the user follows loads nothing until they follow it, in a page of their own. What bounds
     * those is that the URLs are HTTPS, read at the registration like every other URL a client
     * registers, and that the page sends no referrer with them.
     */
    public function contentSecurityPolicy(): string
    {
        $origins = [];
        if ($this->presentation->logoUri !== null) {
            $origins[] = $this->presentation->logoUri->origin;
        }
        if ($this->look->logoUri !== null) {
            $origins[] = $this->look->logoUri->origin;
        }
        // a tenant that serves its logo from where the client serves its own names that origin once: a
        // source expression repeated is the same source, and a policy says what it allows one time
        $origins = array_values(array_unique($origins));

        return sprintf("img-src 'self'%s; frame-ancestors 'none'", $origins === [] ? '' : ' ' . implode(' ', $origins));
    }
}
