<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Exception\UnreadableClientMetadataException;

/**
 * OIDC Core §8
 */
interface SubjectIdentifierKindInterface extends SubjectIdentifierResolverInterface, SubjectIdentifierOpenerInterface, PresentedSubjectReaderInterface
{
    /**
     * @return non-empty-string
     */
    public function subjectType(): string;

    /**
     * Refuses a client that registered nothing this kind computes from, rather than drawing its identifier from
     * something else (OIDC Core §8.1).
     *
     * @throws UnreadableClientMetadataException
     */
    public function assertAssignable(ClientRegistration $registration): void;
}
