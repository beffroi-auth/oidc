<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Flow;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Domain\Flow\Hop;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\FlowPicturesInterface;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use function sprintf;

final readonly class WiredFlowPictures implements FlowPicturesInterface
{
    /**
     * @param iterable<FlowShapeInterface> $openings how a flow reaches a token, one per grant
     * @param iterable<FlowShapeInterface> $closings what is then done with the token
     */
    public function __construct(
        private ServedGrantsInterface $served,
        private iterable $openings,
        private iterable $closings,
    ) {
    }

    public function pictures(): array
    {
        $pictures = [];
        foreach ($this->served->servedGrantTypes() as $grantType) {
            $pictures[] = new FlowPicture($grantType, [
                ...$this->opening($grantType),
                ...$this->closing($grantType),
            ]);
        }
        /** @var non-empty-list<FlowPicture> $pictures */
        return $pictures;
    }

    public function of(GrantTypeName $grantType): ?FlowPicture
    {
        foreach ($this->pictures() as $picture) {
            if ($picture->grantType->equals($grantType)) {
                return $picture;
            }
        }

        return null;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return non-empty-list<Hop>
     */
    private function opening(GrantTypeName $grantType): array
    {
        $opening = null;
        foreach ($this->openings as $shape) {
            if (! $this->draws($shape, $grantType)) {
                continue;
            }
            if ($opening !== null) {
                throw new InvalidArgumentException(sprintf(
                    'The flow of "%s" is opened by two shapes: a grant declares one way of reaching a token.',
                    $grantType->value,
                ));
            }
            $opening = $shape->hops();
        }
        if ($opening === null) {
            throw new InvalidArgumentException(sprintf('The flow of "%s" is opened by no wired shape.', $grantType->value));
        }

        return $opening;
    }

    /**
     * @throws InvalidArgumentException
     *
     * @return list<Hop>
     */
    private function closing(GrantTypeName $grantType): array
    {
        $hops = [];
        foreach ($this->closings as $shape) {
            if ($this->draws($shape, $grantType)) {
                $hops = [...$hops, ...$shape->hops()];
            }
        }

        return $hops;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function draws(FlowShapeInterface $shape, GrantTypeName $grantType): bool
    {
        return array_any($shape->grantTypes($this->served), fn ($drawn) => $drawn->equals($grantType));
    }
}
