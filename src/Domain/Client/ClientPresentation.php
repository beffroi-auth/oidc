<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use function in_array;

/**
 * OIDC Registration §2
 */
final readonly class ClientPresentation
{
    /**
     * @var list<string>
     */
    public array $contacts;

    /**
     * @param string $name "client_name", or the client identifier when none was registered
     * @param list<string> $contacts
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
