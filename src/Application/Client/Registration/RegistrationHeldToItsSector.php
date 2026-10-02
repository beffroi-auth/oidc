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
 *
 * **Which URIs the document must list is the sources' to say and not this class's** (`SectorIdentifiers`):
 * what a client publishes to back its claim is what it would otherwise have been judged on, so an ordinary
 * client publishes its redirection URIs (OIDC Registration §5) and a client that registers none publishes
 * the "jwks_uri" its sector would have been read from (CIBA Core §4). A source wired later is asked for its
 * own the same way, and nothing here enumerates them.
 */
final readonly class RegistrationHeldToItsSector
{
    public function __construct(
        private SectorIdentifierDocumentFetcherInterface $documents,
        private SectorIdentifiersInterface $sectors,
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
