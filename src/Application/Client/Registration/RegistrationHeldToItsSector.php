<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use function in_array;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Heidi\Oidc\Exception\InvalidClientMetadataException;
use Heidi\Oidc\Exception\SectorIdentifierUnavailableException;
use Heidi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use function sprintf;

/**
 * OIDC Registration §5: a client that registers a "sector_identifier_uri" publishes, behind it, the JSON
 * array of the redirection URIs of the clients of that sector, and every URI it registers is in that array.
 *
 * It is what makes a sector a claim a client can back rather than a string it wrote. A sector decides which
 * clients see a user under the same pairwise identifier (OIDC Core §8.1), so a client able to name any
 * sector could put itself in somebody else's and read their users under their own identifiers. Publishing on
 * the host of the sector is the proof, and it is asked for once, when the registration is written.
 *
 * It is read here, for a registration the provider is about to write, the creation of RFC 7591 §3.1 and the
 * replacement of RFC 7592 §2.2, and nowhere else: reading a stored client back is not the moment a claim is
 * made, and a declaration of a deployment claims nothing, the deployment being the authority over what it
 * declares. A document that cannot be read is a refusal and never a client registered anyway.
 */
final readonly class RegistrationHeldToItsSector
{
    public function __construct(
        private SectorIdentifierDocumentFetcherInterface $documents,
    ) {
    }

    /**
     * @throws InvalidClientMetadataException when the sector cannot be read, or does not name this client
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
        foreach ($registration->redirectUris as $redirectUri) {
            if (! in_array($redirectUri->value, $listed, true)) {
                throw $this->refusal($metadata, sprintf(
                    'The document at %s does not list the redirection URI "%s" of the client "%s" (OIDC Registration section 5).',
                    $sectorIdentifierUri->value,
                    $redirectUri->value,
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
