<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;

/**
 * An administrator does not take away what they act with: disabling their own account would end the session they act
 * from, and leaving a group whose members administer the tenant would end their role, the tenant left with nobody to
 * give it back but the operator of the instance.
 */
final class OwnAccountRefusedException extends RuntimeException implements ExceptionInterface
{
}
