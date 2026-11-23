<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Disclosure;

use Beffroi\Core\Domain\Chain\ChainInterface;

final readonly class DisclosureChain implements ChainInterface
{
    public const string NAME = 'disclosures';

    public function name(): string
    {
        return self::NAME;
    }
}
