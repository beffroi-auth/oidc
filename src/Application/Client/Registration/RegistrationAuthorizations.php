<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function array_keys;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use function implode;
use function sprintf;

/**
 * The ways a registration may be authorised that the wiring gave the provider (decision 0009), each
 * under the name it gives itself. The one source of truth over them: a registration policy names one of
 * these names, and what serves it is looked up here rather than decided anywhere by a case.
 *
 * A policy that names a mode nothing serves is a deployment that wired one thing and wrote another, and
 * it is told which modes it wired.
 */
final readonly class RegistrationAuthorizations
{
    /**
     * @var array<string, RegistrationAuthorizationInterface>
     */
    private array $modes;

    /**
     * @param iterable<RegistrationAuthorizationInterface> $modes in the order they are wired
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
