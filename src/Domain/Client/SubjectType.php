<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client;

/**
 * The kind of "sub" a client is registered to see (OIDC Core §8, OIDC Registration §2 "subject_type"): the
 * same identifier for that user whoever asks, or one per client or group of clients. A closed set the
 * specification fixes, and one of the two values a client may register.
 *
 * Which of them this provider assigns a "sub" for is what it announces in "subject_types_supported", and a
 * client that registers the other one is refused rather than served an identifier of the kind it did not
 * ask for.
 */
enum SubjectType: string
{
    /**
     * OIDC Core §8: the same "sub" for that user to every client of the tenant.
     */
    case Public = 'public';

    /**
     * OIDC Core §8.1: a "sub" per sector, computed from the sector the client belongs to, so that two
     * clients of two sectors cannot recognise the same user from what they were told.
     */
    case Pairwise = 'pairwise';

    /**
     * The kinds this provider resolves a "sub" for, in the order it announces them. What resolves one is a
     * class the wiring holds (SubjectIdentifierResolverInterface), and the day there is one per kind this
     * reads the wired ones instead of naming them.
     *
     * @return non-empty-list<self>
     */
    public static function assigned(): array
    {
        return [self::Public];
    }
}
