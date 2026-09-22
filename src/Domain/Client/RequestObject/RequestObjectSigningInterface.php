<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\RequestObject;

/**
 * What a client registered in "request_object_signing_alg" (OIDC Registration §2), which is what its
 * request objects are read under (RFC 9101 §6.1). A registration is a class implementing this
 * interface: a client that registered nothing, one that registered an algorithm, and the named exception
 * of decision 0006, a client that registered "none" and whose objects are read unsigned. A fourth kind
 * would be a fourth class, never a case added to an enumeration.
 */
interface RequestObjectSigningInterface
{
    /**
     * Whether a request object carrying that "alg" is one this client registered. Nothing else decides
     * it: an object signed with an algorithm the client did not register is refused unread, whatever its
     * signature is worth.
     *
     * @param string|null $algorithm the "alg" of the protected header, null when it names none
     * @param list<non-empty-string> $wired the algorithms the provider verifies signatures with
     */
    public function accepts(?string $algorithm, array $wired): bool;

    /**
     * Whether this client registered the named exception: a request object it does not sign (OIDC
     * Registration §2, "none"). It is what the discovery document announces "none" for, and what lets an
     * unsigned object be read instead of being refused unread.
     */
    public function acceptsUnsigned(): bool;

    /**
     * Whether the registration only makes sense for a client that publishes keys of its own (RFC 7591
     * §2), which is what makes a registration naming an algorithm fail at boot when nothing would verify
     * it.
     */
    public function needsPublishedKeys(): bool;
}
