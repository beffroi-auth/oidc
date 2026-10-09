<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function sprintf;

/**
 * The picture of one flow this provider serves (issue #462): the grant whose shape it is, and the hops
 * of that flow in the order they happen. It says what the flow is made of; what travelled in a hop is
 * the business of whoever recorded one, never of the picture.
 *
 * The actors are read from the hops, in the order the drawing declares them: a picture has the columns
 * its own exchanges need, and no flow is given a party it never speaks to.
 */
final readonly class FlowPicture
{
    /**
     * @param non-empty-list<Hop> $hops
     *
     * @throws InvalidArgumentException when the flow is drawn without a single hop
     */
    public function __construct(
        public GrantTypeName $grantType,
        public array $hops,
    ) {
        if ($hops === []) {
            throw new InvalidArgumentException(sprintf('The flow of "%s" is drawn with at least one hop.', $grantType->value));
        }
    }

    /**
     * @return list<Actor>
     */
    public function actors(): array
    {
        $touched = [];
        foreach (Actor::cases() as $actor) {
            foreach ($this->hops as $hop) {
                if ($hop->from === $actor || $hop->to === $actor) {
                    $touched[] = $actor;

                    break;
                }
            }
        }
        return $touched;
    }

    /**
     * @return non-empty-list<non-empty-string>
     */
    public function hopNames(): array
    {
        $names = [];
        foreach ($this->hops as $hop) {
            $names[] = $hop->name;
        }
        /** @var non-empty-list<non-empty-string> $names */
        return $names;
    }

    public function draws(string $hopName): bool
    {
        return in_array($hopName, $this->hopNames(), true);
    }
}
