<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Interaction;

/**
 * Why the user has to consent before the request goes further; with prompt=none it becomes
 * "consent_required".
 */
enum ConsentRequirement: string
{
    /**
     * No consent in force covers every scope of the request.
     */
    case NotGranted = 'not_granted';

    /**
     * OIDC Core §3.1.2.1 prompt=consent: the client asks for the question to be put again.
     */
    case ConsentRequested = 'consent_requested';
}
