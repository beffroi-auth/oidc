<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Bridge\Configuration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Application\Client\ClientMetadataReader;
use Beffroi\Oidc\Application\Client\Method\SecretKeepingMethodInterface;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\Metadata\ClientMetadata;
use Beffroi\Oidc\Domain\Client\Metadata\DeclaredMembers;
use Beffroi\Oidc\Domain\Client\Metadata\DeploymentDefaults;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use function is_string;
use function preg_match;
use SensitiveParameter;
use function sprintf;

/**
 * One client as the configuration declares it (architecture §5.1). What it adds to the registration the
 * reader builds is the one thing RFC 7591 §2 has no member for and only a deployment writes: the secret it
 * chose for that client, kept in clear until the client is built and hashed once, when it is.
 *
 * Everything else is the metadata of a registration and is read where all of it is read
 * (`ClientMetadataReader`), behind the defaults a deployment means when it writes nothing
 * (`DeploymentDefaults`). A declaration that does not hold together stops the boot, which is the one thing
 * this caller does with a refusal the reader knows nothing about.
 */
final readonly class ClientDefinition
{
    /**
     * RFC 6749 appendix A.2, at least 32 characters (RFC 6819 §5.1.4.2.2).
     */
    private const string SECRET_PATTERN = '/^[\x21-\x7E]{32,}$/D';

    private function __construct(
        #[SensitiveParameter]
        private ?string $secret,
        public ClientRegistration $registration,
    ) {
    }

    /**
     * @param array<string, mixed> $definition the members of RFC 7591 §2 the deployment declared, and the secret it chose
     *
     * @throws InvalidArgumentException when the declaration does not hold together, which stops the boot
     */
    public static function fromArray(string $clientId, array $definition, ClientMetadataReader $reader): self
    {
        $secret = $definition['secret'] ?? null;
        unset($definition['secret']);
        if ($secret !== null) {
            if (! is_string($secret)) {
                throw new InvalidArgumentException(sprintf('The secret of the client "%s" must be a string.', $clientId));
            }
            if (preg_match(self::SECRET_PATTERN, $secret) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'The secret of the client "%s" must be at least 32 visible ASCII characters long; generate it, do not choose it.',
                    $clientId,
                ));
            }
        }

        return new self(
            $secret,
            $reader->read($clientId, new ClientMetadata([new DeclaredMembers($definition), new DeploymentDefaults()]), $secret !== null),
        );
    }

    public function hasSecret(): bool
    {
        return $this->secret !== null;
    }

    /**
     * The registered secret in the shape the method it registered verifies against. As costly as hashing
     * a password when the method keeps a hash: once per process.
     *
     * @throws LogicException for a client whose method proves no secret
     */
    public function keepSecret(PasswordHasherInterface $hasher): ClientSecretInterface
    {
        $method = $this->registration->authenticationMethod;
        if ($this->secret === null || ! $method instanceof SecretKeepingMethodInterface) {
            throw new LogicException(sprintf('The client "%s" registers no secret to keep.', $this->registration->clientId));
        }

        return $method->keep($this->secret, $hasher);
    }

    public function toClient(Tenant $tenant, ?ClientSecretInterface $secret): Client
    {
        return new Client($tenant, $this->registration, $secret);
    }
}
