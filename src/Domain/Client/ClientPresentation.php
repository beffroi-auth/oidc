<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client;

use function array_unique;
use function array_values;

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
        $this->contacts = array_values(array_unique($contacts));
    }
}
