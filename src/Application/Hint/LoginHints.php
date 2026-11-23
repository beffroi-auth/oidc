<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Hint;

use function count;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Application\Consent\SharedIdentity;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function sprintf;

/**
 * OIDC Core §3.1.2.1, decision 0006
 *
 * A hint names only a person the client may be told of, the login page offering whoever it names.
 */
final readonly class LoginHints
{
    public const string PARAMETER = 'login_hint';

    /**
     * @param iterable<UserHintInterface> $readings
     */
    public function __construct(
        private iterable $readings,
        private SharedIdentity $sharedIdentity,
    ) {
    }

    /**
     * @throws LogicException when two readings are wired for the parameter
     */
    public function userNamedBy(AuthorizationRequest $request): ?User
    {
        $hint = $request->loginHint;
        if ($hint === null || $hint === '') {
            return null;
        }
        $reading = $this->reading();
        if ($reading === null) {
            return null;
        }

        try {
            $user = $reading->userNamedBy($request->client, $hint);
        } catch (OAuth2Exception) {
            // OIDC Core §3.1.2.1: a hint is only a hint, so a value the reading refuses names nobody.
            return null;
        }

        return $user !== null && $this->sharedIdentity->isSharedWith($user, $request->client) ? $user : null;
    }

    /**
     * @throws LogicException
     */
    private function reading(): ?UserHintInterface
    {
        $reading = [];
        foreach ($this->readings as $hint) {
            if ($hint->parameterName() === self::PARAMETER) {
                $reading[] = $hint;
            }
        }
        if (count($reading) > 1) {
            throw new LogicException(sprintf(
                'Two hints are wired to read the %s parameter of an authorization request; a hint is read one way.',
                self::PARAMETER,
            ));
        }

        return $reading[0] ?? null;
    }
}
