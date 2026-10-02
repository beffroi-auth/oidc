<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Client\Metadata;

/**
 * One source of the metadata a client is registered with (RFC 7591 §2): a set of members under their
 * registered names, and what to call it where a value of it is named in a refusal.
 *
 * There is more than one because RFC 7591 §3.1.1 makes it so: the members of a statement its issuer signed
 * take precedence over the same members sent in the clear, so a source is added in front of another and
 * never merged into it. What each source carries is its own business, the names are the specification's,
 * and which of them wins is the order they are read in (ClientMetadata).
 */
interface ClientMetadataSourceInterface
{
    /**
     * Where these members came from, as a refusal names it.
     *
     * @return non-empty-string
     */
    public function source(): string;

    /**
     * @return array<string, mixed> the members this source carries, under the names of RFC 7591 §2; a
     *                             member it carries as null is a member it does not carry
     */
    public function members(): array;
}
