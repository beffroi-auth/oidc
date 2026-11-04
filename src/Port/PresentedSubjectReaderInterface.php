<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;

/**
 * A "sub" is read for the client that presented it and never as a row key: under a pairwise kind, a "sub" of one
 * client presented by another names nobody (OIDC Core §8.1).
 */
interface PresentedSubjectReaderInterface
{
    public function findUser(Client $client, Subject $subject): ?User;
}
