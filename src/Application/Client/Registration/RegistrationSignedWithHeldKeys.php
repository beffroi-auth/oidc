<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Application\Key\HeldSigningAlgorithms;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\SignedDocument;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use function sprintf;

/**
 * Refuses a registration that names, for its ID tokens, its authorization responses or its UserInfo responses, a
 * signature algorithm its tenant holds no active key for: the first of them would fail when it is issued, long after
 * the registration was accepted. An algorithm left unnamed is the default one, which is the deployment's to hold a key
 * for and never the client's.
 */
final readonly class RegistrationSignedWithHeldKeys
{
    public function __construct(
        private HeldSigningAlgorithms $held,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException
     */
    public function assertHolds(Tenant $tenant, ClientRegistration $registration, ClientMetadata $metadata): void
    {
        foreach (SignedDocument::of($registration) as $document) {
            $algorithm = $document->format->signature;
            if ($algorithm === null || ! $metadata->has($document->member) || $this->held->holds($tenant, $algorithm)) {
                continue;
            }

            throw new InvalidClientMetadataException(
                $document->member,
                $metadata->sourceOf($document->member),
                sprintf(
                    'The client "%s" would receive its %s signed with %s, which this tenant holds no active key for.',
                    $registration->clientId,
                    $document->documents,
                    $algorithm->name(),
                ),
            );
        }
    }
}
