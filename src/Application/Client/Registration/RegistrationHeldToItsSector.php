<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use function in_array;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use function sprintf;

/**
 * OIDC Registration §5
 *
 * A sector document that cannot be read refuses the registration.
 */
final readonly class RegistrationHeldToItsSector
{
    public function __construct(
        private SectorIdentifierDocumentFetcherInterface $documents,
        private SectorIdentifiersInterface $sectors,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException
     */
    public function assertHolds(ClientRegistration $registration, ClientMetadata $metadata): void
    {
        $sectorIdentifierUri = $registration->sectorIdentifierUri;
        if ($sectorIdentifierUri === null) {
            return;
        }
        try {
            $listed = $this->documents->fetch($sectorIdentifierUri);
        } catch (SectorIdentifierUnavailableException $exception) {
            throw $this->refusal($metadata, $exception->getMessage(), $exception);
        }
        foreach ($this->sectors->publishedUris($registration) as $uri) {
            if (! in_array($uri, $listed, true)) {
                throw $this->refusal($metadata, sprintf(
                    'The document at %s does not list the URI "%s" of the client "%s" (OIDC Registration section 5, CIBA Core section 4).',
                    $sectorIdentifierUri->value,
                    $uri,
                    $registration->clientId,
                ));
            }
        }
    }

    private function refusal(
        ClientMetadata $metadata,
        string $message,
        ?SectorIdentifierUnavailableException $previous = null,
    ): InvalidClientMetadataException {
        return new InvalidClientMetadataException(
            'sector_identifier_uri',
            $metadata->has('sector_identifier_uri') ? $metadata->sourceOf('sector_identifier_uri') : null,
            $message,
            $previous,
        );
    }
}
