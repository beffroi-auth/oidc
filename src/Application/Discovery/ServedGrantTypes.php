<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Discovery;

use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Application\Token\GrantInterface;

/**
 * The grants the token endpoint serves, named by the grants themselves: the same iterator the endpoint
 * is given, so the document cannot announce a grant the endpoint refuses. Two members read it, the list
 * of grant types and the "offline_access" scope that only a refresh token grant makes good on.
 */
final readonly class ServedGrantTypes
{
    /**
     * @var non-empty-list<GrantType>
     */
    public array $all;

    /**
     * @param iterable<GrantInterface> $grants the grants of the token endpoint, at least one
     *
     * @throws InvalidArgumentException when none is wired
     */
    public function __construct(iterable $grants)
    {
        $types = [];
        foreach ($grants as $grant) {
            $types[] = $grant->grantType();
        }
        if ($types === []) {
            throw new InvalidArgumentException('The token endpoint serves at least one grant.');
        }
        $this->all = $types;
    }
}
