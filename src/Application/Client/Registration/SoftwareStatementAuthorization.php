<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Beffroi\Oidc\Exception\InvalidClientMetadataException;
use Beffroi\Oidc\Exception\InvalidSoftwareStatementException;
use Beffroi\Oidc\Exception\UnauthorizedRegistrationException;
use function is_string;
use Psr\Clock\ClockInterface;

/**
 * RFC 7591 §2.3, §3.1.1
 */
final readonly class SoftwareStatementAuthorization implements RegistrationAuthorizationInterface
{
    public const string MODE = 'software_statement';

    public const string MEMBER = 'software_statement';

    public function __construct(
        private SoftwareStatementVerifier $statements,
        private ClockInterface $clock,
    ) {
    }

    public function name(): string
    {
        return self::MODE;
    }

    /**
     * @throws UnauthorizedRegistrationException when the body carries no statement
     * @throws InvalidSoftwareStatementException
     * @throws InvalidClientMetadataException when the statement carries a member of this provider alone
     */
    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): AuthorizedRegistration
    {
        $presented = $request->members()[self::MEMBER] ?? null;
        if (! is_string($presented) || $presented === '') {
            throw new UnauthorizedRegistrationException();
        }

        return new AuthorizedRegistration([$this->statements->verify($tenant, $policy, $presented, $this->clock->now())]);
    }
}
