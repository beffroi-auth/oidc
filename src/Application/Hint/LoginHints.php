<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Hint;

use function count;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function sprintf;

/**
 * The way this provider is wired to read the "login_hint" of an authorization request (OIDC Core
 * §3.1.2.1), and the one thing it is read for: the user it names, so that the page waiting for a login
 * can offer the name that user signs in with rather than the value the client sent. It is what makes the
 * hint this provider writes itself worth carrying, a login begun at the client naming its user by the
 * "sub" that client holds (OIDC Core §4).
 *
 * The hint names nobody when the request carries none, when nothing is wired to read it, when the value
 * is not of the shape the wired reading reads, and when it reads a user this client was never handed
 * (OIDC Core §8). Those are one answer, and the page that follows it is the page a request carrying no
 * hint at all renders: a hint is a hint, so what it names is offered and never trusted, and what it fails
 * to name costs the request nothing.
 */
final readonly class LoginHints
{
    /**
     * OIDC Core §3.1.2.1, the same parameter CIBA Core §7.1 names.
     */
    public const string PARAMETER = 'login_hint';

    /**
     * @param iterable<UserHintInterface> $readings in the order they are wired
     */
    public function __construct(
        private iterable $readings,
    ) {
    }

    /**
     * @throws LogicException when two readings are wired for the parameter, which is a wiring that has
     *                        two answers to one question
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
            return $reading->userNamedBy($request->client, $hint);
        } catch (OAuth2Exception) {
            // OIDC Core §3.1.2.1 makes this parameter a hint: a value the reading refuses is a value that
            // names nobody, and never an authorization request refused for what it was only offered
            return null;
        }
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
