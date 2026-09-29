<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Ciba;

use function count;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Application\Hint\UserHintInterface;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Exception\InvalidRequestException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function sprintf;

/**
 * The ways this provider is wired to read the user a backchannel authentication request is made for
 * (CIBA Core §7.1), and the one rule that governs all of them: a request carries exactly one hint.
 *
 * Which parameters count as a hint is the specification's closed list and not the wiring's: a request
 * carrying a hint this provider does not read, beside one it does, names its user twice and is refused
 * for that, not served on the half it happens to understand. A request carrying only a hint that is not
 * read here is refused as well, and neither refusal has looked up anybody.
 */
final readonly class UserHints
{
    /**
     * CIBA Core §7.1: "the Client MUST provide one (and only one) of the hints", and these are the three.
     */
    public const array HINT_PARAMETERS = ['login_hint_token', 'id_token_hint', 'login_hint'];

    /**
     * @param iterable<UserHintInterface> $hints in the order they are wired
     */
    public function __construct(
        private iterable $hints,
    ) {
    }

    /**
     * The user the request names, null when the hint it carries names nobody.
     *
     * @throws OAuth2Exception when the request names no user, names one in more than one way, or names
     *                         one in a way this provider does not read
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
     * @throws LogicException when two wired hints read the same one, which is a wiring that has two
     *                        answers to one question
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
