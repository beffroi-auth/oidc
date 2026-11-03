<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientUri;

/**
 * What the consent page shows of the client that is asking (OIDC Registration §2): the logo, the pages
 * the user may read before deciding, and the origin that image is served from. The name is shown
 * whatever the client registered, so it is read from the presentation and needs nothing here.
 *
 * What the page is made of is fixed in the module, and what it costs is a stranger: the image is served
 * by a host the client named, so the browser of the user fetches it and that host learns the address of
 * the user and the moment the page was shown, whether or not consent follows. That is the price of
 * showing a logo at all, and it is bounded rather than removed: the origin below is the origin of that
 * one image, so nothing a client registers makes the page load anything else. The logo of the tenant is
 * on this page as on every other, and named by whatever page reads it (App\Twig\TenantExtension).
 *
 * The provider fetches none of it. A logo read and cached here would be an outbound request on a URL a
 * client wrote, which is what the "sector_identifier_uri" and the "jwks_uri" rules bound so carefully
 * and what decision 0006 does not spend on a picture. The page names the URL; the browser loads it or
 * does not, and the provider learns nothing either way.
 *
 * The links are in no policy and cannot be: a Content-Security-Policy says what a page loads, and a link
 * the user follows loads nothing until they follow it, in a page of their own. What bounds those is that
 * the URLs are HTTPS, read at the registration like every other URL a client registers, and that the page
 * sends no referrer with them.
 *
 * The page says what it adds and not what the whole policy is, because it is a page of the product: it
 * extends the layout an application overrides (architecture §5.2), so the policy its answer carries is
 * the one of its deployment, completed with this origin and with the origin the submission of the page
 * may end at (App\Http\ImageSource, FormTarget). The two pages that carry a step of the
 * protocol are the ones that write a whole policy, "default-src 'none'" and a named script hash being
 * what they mean (FormPostResponse, FrontChannelLogoutPage).
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
     * @var list<string> where the images of the client on this page are served from: its logo, as an
     *                   origin and never as a URL, which is what a source expression names (RFC 6454
     *                   §3.2, CSP Level 3 §2.3). A client that registered no logo leaves a page that loads
     *                   no image of its own and names nothing
     */
    public array $imageOrigins;

    public function __construct(
        public ClientPresentation $presentation,
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

        $this->imageOrigins = $presentation->logoUri === null ? [] : [$presentation->logoUri->origin];
    }
}
