<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Metadata;

/**
 * Why a registration was refused (RFC 7591 §3.2.2), which is what the endpoint answers in the "error" of
 * its 400 and what a boot puts in nothing at all. A closed set the specification fixes: the two codes below
 * are the ones a set of members can be refused with, the two about a signed statement belonging to the
 * source that verifies one.
 */
enum RegistrationError: string
{
    /**
     * One of the redirection URIs is invalid.
     */
    case InvalidRedirectUri = 'invalid_redirect_uri';

    /**
     * The value of one of the other members is invalid.
     */
    case InvalidClientMetadata = 'invalid_client_metadata';
}
