<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Exception\UnreadableClientMetadataException;

/**
 * The kinds of "sub" the provider is wired to assign (OIDC Core §8), the one source of truth over them: the
 * discovery document announces this list, a registration may name one of these names, and the first of them
 * is the kind a client that registers none takes, as the first wired shape is the shape it takes for its
 * access tokens.
 *
 * A registration that names a kind is read against what that kind needs, here and not at issuance: the list
 * and the reading are the same question asked of the same wiring, so a deployment that wires no pairwise
 * resolver announces "public" alone and refuses a client that asks for pairwise, with nothing kept in
 * parallel to say so.
 */
interface AssignedSubjectTypesInterface
{
    /**
     * @return non-empty-list<non-empty-string> in the order they are wired
     */
    public function assignedSubjectTypes(): array;

    /**
     * @throws UnreadableClientMetadataException when no "sub" of the kind this registration names can be
     *                                          assigned to it
     */
    public function assertAssignable(ClientRegistration $registration): void;
}
