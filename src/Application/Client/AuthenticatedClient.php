<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Token\Confirmation;

/**
 * The client of a request and what it proved beyond being itself (RFC 8705 §3): a method that proves the
 * client holds the private key of a certificate leaves a confirmation here, and the tokens issued on
 * that request carry it. A client authenticated by a secret or by an assertion proves who it is and
 * nothing more, and its tokens are bearer tokens.
 */
final readonly class AuthenticatedClient
{
    public function __construct(
        public Client $client,
        public ?Confirmation $confirmation = null,
    ) {
    }
}
