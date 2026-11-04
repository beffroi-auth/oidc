<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function array_keys;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use function implode;
use function sprintf;

final readonly class RegistrationAuthorizations
{
    /**
     * @var array<string, RegistrationAuthorizationInterface>
     */
    private array $modes;

    /**
     * @param iterable<RegistrationAuthorizationInterface> $modes
     *
     * @throws InvalidArgumentException when two of them answer to one name
     */
    public function __construct(iterable $modes)
    {
        $wired = [];
        foreach ($modes as $mode) {
            $name = $mode->name();
            if (isset($wired[$name])) {
                throw new InvalidArgumentException(sprintf('The client registration mode "%s" is wired twice.', $name));
            }
            $wired[$name] = $mode;
        }
        $this->modes = $wired;
    }

    /**
     * @throws LogicException when nothing wired answers to the mode the policy names
     */
    public function authorizing(ClientRegistrationPolicy $policy): RegistrationAuthorizationInterface
    {
        $mode = $this->modes[$policy->mode] ?? null;
        if ($mode === null) {
            throw new LogicException(sprintf(
                'The registration policy names the mode "%s", which nothing wired here serves; this provider serves %s.',
                $policy->mode,
                $this->modes === [] ? 'none' : implode(', ', array_keys($this->modes)),
            ));
        }

        return $mode;
    }
}
