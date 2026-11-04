<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;

interface UserAuthorizationInterface extends AuthorizationInterface
{
    public AuthenticationSession $session { get; }

    public User $user { get; }

    public ?string $nonce { get; }

    public ?ClaimsRequest $claimsRequest { get; }

    public AuthenticationSnapshot $authentication { get; }

    public ?AuthorizationDetails $authorizationDetails { get; }

    public ?AuthorizationDetails $grantedAuthorizationDetails { get; }
}
