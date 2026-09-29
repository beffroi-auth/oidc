<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Client\Registration;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Heidi\Oidc\Domain\Client\Registration\RegistrationRequest;
use Heidi\Oidc\Exception\InvalidSoftwareStatementException;
use Heidi\Oidc\Exception\UnauthorizedRegistrationException;
use function is_string;
use Psr\Clock\ClockInterface;

/**
 * The fourth mode of decision 0009, and the only one that crosses the boundary of an organisation: a
 * registration authorised by a statement an authority the tenant pinned signed, and not by a credential
 * this provider issued (RFC 7591 §2.3). An initial access token is a secret the provider issues, keeps,
 * counts and revokes for every team that integrates, so it holds inside one organisation and does not
 * scale between them; a statement moves the proof to the authority, and the provider issues nothing.
 *
 * It is the one mode that reads the body rather than the header, and the only one that puts anything in
 * front of the members the client sent: RFC 7591 §3.1.1 makes those two the same decision, so the class
 * that trusts a statement is the class that says its members outrank the ones sent in the clear. That is
 * what closes, for the clients it covers, what the open mode leaves open on the consent page: the
 * `client_name` and the `logo_uri` of an attested client are the ones an authority signed and not the
 * ones the caller typed.
 *
 * A tenant that pins no authority has this mode closed rather than open to whoever signs: nothing
 * verifies, so nothing authorises.
 *
 * What a statement says is what the client **is**; what it **may have** is the policy's, and a statement
 * naming a scope, a grant or an authentication method the tenant does not offer is refused by the same
 * rule and the same code path as a request body naming it. This class grants nothing.
 */
final readonly class SoftwareStatementAuthorization implements RegistrationAuthorizationInterface
{
    /**
     * The name a registration policy names this mode by (decision 0009).
     */
    public const string MODE = 'software_statement';

    /**
     * RFC 7591 §2.3: the member the statement arrives in.
     */
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
     * @throws UnauthorizedRegistrationException when the body carries no statement at all, which is a
     *                                           request that presents nothing this mode acts on
     * @throws InvalidSoftwareStatementException when it carries one this tenant does not accept
     */
    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): array
    {
        $presented = $request->members()[self::MEMBER] ?? null;
        if (! is_string($presented) || $presented === '') {
            throw new UnauthorizedRegistrationException();
        }

        return [$this->statements->verify($tenant, $policy, $presented, $this->clock->now())];
    }
}
