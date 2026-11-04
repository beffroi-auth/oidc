<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\OAuth2Exception;
use SensitiveParameter;

/**
 * OIDC Core §3.1.2.1, CIBA Core §7.1
 */
interface UserHintInterface
{
    public function parameterName(): string;

    /**
     * Naming nobody and naming somebody who does not answer are one answer, null (decision 0006).
     *
     * @throws OAuth2Exception when the value is not of the shape this hint reads
     */
    public function userNamedBy(Client $client, #[SensitiveParameter] string $value): ?User;
}
