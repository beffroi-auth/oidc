<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Consent;

use Beffroi\Oidc\Domain\Event\ConsentGranted;
use Beffroi\Oidc\Domain\Event\ConsentRevoked;

/**
 * The acts of the consents of a person, which the page of their acts lists whoever made them: the person on the page
 * of their applications, the operator of the instance at the console, or an administrator through the administration
 * API (decision 0038).
 */
final class ConsentActs
{
    /**
     * @var list<string>
     */
    public const array NAMES = [
        ConsentGranted::NAME,
        ConsentRevoked::NAME,
    ];
}
