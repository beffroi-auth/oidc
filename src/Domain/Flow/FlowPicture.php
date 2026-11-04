<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use function in_array;
use function sprintf;

final readonly class FlowPicture
{
    /**
     * @param non-empty-list<Hop> $hops
     *
     * @throws InvalidArgumentException
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
