<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Interaction;

/**
 * Why the user has to consent; with prompt=none it becomes "consent_required".
 */
enum ConsentRequirement: string
{
    case NotGranted = 'not_granted';

    /**
     * OIDC Core §3.1.2.1 prompt=consent.
     */
    case ConsentRequested = 'consent_requested';
}
