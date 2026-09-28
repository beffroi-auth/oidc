<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Core\Domain\Identity\Subject;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Client\Client;

/**
 * The "sub" a client sees for a user (OIDC Core §8); every token and UserInfo response go through it (§5.3.2).
 *
 * A kind of "sub" is a class that resolves one, never a case of an enumeration: what the provider assigns is
 * what the wiring holds, so the kinds it announces in "subject_types_supported" and the kinds a client may
 * register are read from the resolvers themselves.
 */
interface SubjectIdentifierResolverInterface
{
    /**
     * The kind of "sub" this resolves, under the name OIDC Core §8 gives it and a client registers it by
     * ("subject_type", OIDC Registration §2).
     *
     * @return non-empty-string
     */
    public function subjectType(): string;

    public function resolve(User $user, Client $client): Subject;
}
