<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Ciba;

use function count;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Application\Hint\UserHintInterface;
use Beffroi\Oidc\Application\Request\RequestParameters;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Exception\InvalidRequestException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use function sprintf;

final readonly class UserHints
{
    /**
     * CIBA Core §7.1
     *
     * The specification's list, not the wiring's: an unread hint beside a read one still names the user twice.
     */
    public const array HINT_PARAMETERS = ['login_hint_token', 'id_token_hint', 'login_hint'];

    /**
     * @param iterable<UserHintInterface> $hints
     */
    public function __construct(
        private iterable $hints,
    ) {
    }

    /**
     * @throws OAuth2Exception
     */
    public function userNamedBy(Client $client, RequestParameters $request): ?User
    {
        $carried = [];
        foreach (self::HINT_PARAMETERS as $parameter) {
            if ($request->isPresent($parameter)) {
                $carried[] = $parameter;
            }
        }
        if (count($carried) !== 1) {
            throw new InvalidRequestException('A backchannel authentication request names the user it is made for once, by one of login_hint_token, id_token_hint and login_hint (CIBA Core section 7.1).');
        }
        $parameter = $carried[0];

        return $this->reading($parameter)->userNamedBy($client, $request->required($parameter));
    }

    /**
     * @throws InvalidRequestException when nothing wired reads that parameter
     * @throws LogicException when two wired hints read it
     */
    private function reading(string $parameter): UserHintInterface
    {
        $reading = [];
        foreach ($this->hints as $hint) {
            if ($hint->parameterName() === $parameter) {
                $reading[] = $hint;
            }
        }
        if (count($reading) > 1) {
            throw new LogicException(sprintf(
                'Two hints are wired to read the %s parameter of a backchannel authentication request; a hint is read one way.',
                $parameter,
            ));
        }

        return $reading[0] ?? throw new InvalidRequestException(sprintf(
            'This provider does not read the %s parameter of a backchannel authentication request (CIBA Core section 7.1).',
            $parameter,
        ));
    }
}
