<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;

/**
 * RFC 6749 §4.1.2, §4.1.2.1
 */
final readonly class AuthorizationAnswer
{
    /**
     * JARM §2.1
     */
    public const string DOCUMENT_PARAMETER = 'response';

    /**
     * @var non-empty-array<string, string>
     */
    public array $parameters;

    /**
     * @param array<string, string> $parameters "iss" included
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
     * JARM §2.1
     */
    public function signedWith(string $document): self
    {
        return new self($this->client, $this->redirectUri, [
            self::DOCUMENT_PARAMETER => $document,
        ]);
    }
}
