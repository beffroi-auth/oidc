<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

use function in_array;

/**
 * What a registration says about who is asking (OIDC Registration §2): the name a user reads on the consent
 * page, the pages that page links to, and how to reach whoever answers for the client. Every URL of it is a
 * URL a client registers, read as every other one is (ClientUri), so a logo served in plain HTTP on a name
 * is refused at the registration and not loaded into a page later.
 *
 * What a page does with them is the page's; what they are is here. The contacts are the one member of the
 * group no page shows: they name the people responsible for the client, for whoever runs the provider.
 *
 * Whether what it holds is enough is the registration's (ClientRegistration): it is the value that answers
 * for itself, and it is the one that can name the client in a refusal.
 */
final readonly class ClientPresentation
{
    /**
     * @var list<string> each once, in the order they were registered
     */
    public array $contacts;

    /**
     * @param string $name shown on the consent page ("client_name"); the client identifier for a client that registered none
     * @param ClientUri|null $uri the home page of the client ("client_uri")
     * @param ClientUri|null $logoUri the logo the consent page shows ("logo_uri")
     * @param ClientUri|null $policyUri how the client uses the data it is given ("policy_uri")
     * @param ClientUri|null $tosUri the terms of service of the client ("tos_uri")
     * @param list<string> $contacts ways to reach the people responsible for the client ("contacts")
     */
    public function __construct(
        public string $name,
        public ?ClientUri $uri = null,
        public ?ClientUri $logoUri = null,
        public ?ClientUri $policyUri = null,
        public ?ClientUri $tosUri = null,
        array $contacts = [],
    ) {
        $kept = [];
        foreach ($contacts as $contact) {
            if (! in_array($contact, $kept, true)) {
                $kept[] = $contact;
            }
        }
        $this->contacts = $kept;
    }
}
