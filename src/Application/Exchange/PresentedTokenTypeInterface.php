<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Exchange;

use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Exchange\PresentedToken;
use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidRequestException;
use SensitiveParameter;

/**
 * One type of token the exchange accepts (RFC 8693 §3), called with what the request presented as a
 * "subject_token" or as an "actor_token".
 *
 * One class per type, wired into the provider: the type names itself, and what the exchange accepts and what
 * a client may register in its "subject_token_types" are that one wired list. A type the provider gains is a
 * class added to the wiring, never a case added to an enumeration, and what it reads of its own tokens is
 * its own business: the grant reads a PresentedToken and never the type that produced it.
 */
interface PresentedTokenTypeInterface
{
    /**
     * The identifier of RFC 8693 §3 this type answers to, compared byte for byte with what a request wrote.
     */
    public function identifier(): TokenTypeIdentifier;

    /**
     * @param string $token the value the request presented
     *
     * @throws InvalidRequestException when the value is not a token of this type, or is one this provider
     *                                 no longer honours, which RFC 8693 §2.2.2 answers with
     *                                 "invalid_request" whatever the reason; a client is told that what it
     *                                 presented is not good and nothing more
     */
    public function read(Tenant $tenant, #[SensitiveParameter] string $token, DateTimeImmutable $now): PresentedToken;
}
