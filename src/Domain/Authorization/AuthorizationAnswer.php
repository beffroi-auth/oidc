<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What the authorization endpoint hands to one client, whatever it says: the parameters of a successful
 * response (RFC 6749 §4.1.2) or of a refusal (§4.1.2.1), the client they are meant for and the redirect
 * URI they are delivered to. A mode that signs the answer needs the client, to name the audience of the
 * document and to read the algorithm it registered; a mode that does not, ignores it.
 */
final readonly class AuthorizationAnswer
{
    /**
     * JARM §2.1: a signed answer travels as one parameter, whichever way it is delivered.
     */
    public const string DOCUMENT_PARAMETER = 'response';

    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters the response as the protocol names it, "iss" included (RFC 9207 §2)
     */
    public function __construct(
        public Client $client,
        public RedirectUri $redirectUri,
        array $parameters,
    ) {
        if ($parameters === []) {
            throw new InvalidArgumentException('An answer of the authorization endpoint carries at least one parameter.');
        }
        $this->parameters = $parameters;
    }

    /**
     * The same answer once it has been gathered in a signed document (JARM §2.1): "response" and nothing
     * else, so that neither "state" nor "iss" is ever written beside the document that already carries
     * them.
     */
    public function signedWith(string $document): self
    {
        return new self($this->client, $this->redirectUri, [
            self::DOCUMENT_PARAMETER => $document,
        ]);
    }
}
