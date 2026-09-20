<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Authorization\ResponseMode;

/**
 * The response modes the authorization endpoint can actually answer in (OAuth 2.0 Multiple Response Type
 * Encoding Practices §2.1); the integration wires one way of answering per mode, so it says. What the
 * discovery document announces and what the parser accepts read this one source, so that the document
 * and the endpoint cannot disagree (issue #98).
 */
interface ServedResponseModesInterface
{
    /**
     * @return non-empty-list<ResponseMode>
     */
    public function servedResponseModes(): array;
}
