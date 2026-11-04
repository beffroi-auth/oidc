<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Exception\InvalidDpopProofException;

final readonly class AuthenticatedClient
{
    public function __construct(
        public Client $client,
        public ?ConfirmationInterface $confirmation = null,
    ) {
    }

    /**
     * @throws InvalidDpopProofException when the request proved a possession twice over
     */
    public function alsoProving(?ConfirmationInterface $confirmation): self
    {
        if ($confirmation === null) {
            return $this;
        }
        if ($this->confirmation !== null) {
            throw new InvalidDpopProofException('The tokens of a request are bound to one thing, and this request proves a certificate and a key (RFC 9449 section 5).');
        }

        return new self($this->client, $confirmation);
    }

    /**
     * FAPI 2.0 Security Profile §5.3.1
     */
    public function provesWhatItsClientRequires(): bool
    {
        return ! $this->client->registration->requiresSenderConstrainedTokens || $this->confirmation !== null;
    }

    /**
     * RFC 8705 §3.4, FAPI 1.0 Advanced Final §5.2.2
     */
    public function provesTheCertificateItsTokensAreBoundTo(): bool
    {
        return ! $this->client->registration->requiresCertificateBoundTokens || $this->confirmation?->member() === CertificateConfirmation::MEMBER;
    }
}
