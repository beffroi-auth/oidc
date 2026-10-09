<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Flow\FlowPicture;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * The flows this provider serves, drawn (issue #462). One picture per wired grant, derived from the
 * capabilities that grant declares, exactly as the discovery document announces what is wired: a grant
 * the provider gains brings its picture with it, and a grant unwired takes its picture away.
 */
interface FlowPicturesInterface
{
    /**
     * @throws InvalidArgumentException when the wiring does not hold together
     *
     * @return non-empty-list<FlowPicture> in the order the grants are wired
     */
    public function pictures(): array;

    /**
     * The picture of that grant, null for a grant this provider does not serve.
     *
     * @throws InvalidArgumentException when the wiring does not hold together
     */
    public function of(GrantTypeName $grantType): ?FlowPicture;
}
