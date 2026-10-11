<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Disclosure\Disclosure;
use Symfony\Component\Uid\Uuid;

/**
 * What every application was given of one person (issue #590): the archive they ask for, and the page of
 * their account the day it shows it.
 */
interface DisclosuresOfAPersonInterface
{
    /**
     * Everything that was given of that person, oldest first, in pages: the reading the archive needs
     * (issue #453). The identifier is a UUIDv7, which sorts chronologically, so a page is a lookup past the
     * last row read and never a sort of the whole register.
     *
     * @param Uuid|null $after the last row the caller read, null for the first page
     *
     * @return list<Disclosure> the oldest first
     */
    public function everyDisclosureTo(User $user, int $howMany, ?Uuid $after = null): array;
}
