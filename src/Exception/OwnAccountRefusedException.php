<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Exception;

use RuntimeException;

/**
 * An administrator does not disable the account they act with: the session they act from would end with it, and the
 * tenant could be left with nobody to enable it again but the operator of the instance.
 */
final class OwnAccountRefusedException extends RuntimeException implements ExceptionInterface
{
}
