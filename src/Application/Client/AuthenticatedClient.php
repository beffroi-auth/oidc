<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Token\CertificateConfirmation;
use Beffroi\Oidc\Domain\Token\ConfirmationInterface;
use Beffroi\Oidc\Exception\InvalidDpopProofException;

/**
 * The client of a request and what the request proved beyond it being that client (RFC 8705 §3,
 * RFC 9449 §5): a method that proves the client holds the private key of a certificate leaves a
 * confirmation here, a proof of possession leaves another, and the tokens issued on that request carry
 * it. A client authenticated by a secret or by an assertion, and sending no proof, proves who it is and
 * nothing more, and its tokens are bearer tokens.
 */
final readonly class AuthenticatedClient
{
    public function __construct(
        public Client $client,
        public ?ConfirmationInterface $confirmation = null,
    ) {
    }

    /**
     * The same client, with what the request proved on top of its authentication. A token is bound to
     * one thing: it names it in one "cnf" member, a resource asks for that one thing back, and a request
     * that proved two possessions leaves the provider to choose which of them the client meant. It is
     * refused instead, and a client picks the sender constraint it registered for.
     *
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
     * FAPI 2.0 Security Profile §5.3.1: a client registered for sender-constrained tokens gets them or
     * gets nothing. What the request proved is one confirmation or none, whichever kind it is, so the
     * question is asked of the confirmation being there and never of what it is made of.
     */
    public function provesWhatItsClientRequires(): bool
    {
        return ! $this->client->registration->requiresSenderConstrainedTokens || $this->confirmation !== null;
    }

    /**
     * RFC 8705 §3.4, FAPI 1.0 Advanced Final §5.2.2: a client registered for certificate-bound access
     * tokens gets tokens bound to the certificate it presented or gets nothing. The other rule asks the
     * confirmation to be there and never what it is made of; this one names the member the client
     * registered for, a token bound to a key not being the token that client asked for.
     */
    public function provesTheCertificateItsTokensAreBoundTo(): bool
    {
        return ! $this->client->registration->requiresCertificateBoundTokens || $this->confirmation?->member() === CertificateConfirmation::MEMBER;
    }
}
