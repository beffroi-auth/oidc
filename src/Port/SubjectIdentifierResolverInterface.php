<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * The "sub" a client sees for a user (OIDC Core §8); every token and UserInfo response go through it (§5.3.2).
 *
 * A kind of "sub" is a class that resolves one, never a case of an enumeration (SubjectIdentifierKindInterface):
 * what the provider assigns is what the wiring holds, so the kinds it announces in "subject_types_supported"
 * and the kinds a client may register are read from the resolvers themselves. What a caller of this sees is
 * one resolver, which answers with the kind the client registered; AssignedSubjectIdentifiers is the one that
 * picks among them.
 */
interface SubjectIdentifierResolverInterface
{
    /**
     * @throws InvalidArgumentException when the wiring assigns no identifier of the kind this client
     *                                  registered, which is a deployment that unwired a kind its clients
     *                                  still name
     */
    public function resolve(User $user, Client $client): Subject;
}
