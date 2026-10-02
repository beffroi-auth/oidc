<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Client\Registration;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\ClientRegistrationPolicy;
use Beffroi\Oidc\Domain\Client\Registration\RegistrationRequest;

/**
 * The mode decision 0009 builds second and bounds hardest: a `POST` with no credential at all, which is
 * what the `dynamic_client` variant of the conformance suite sends (RFC 7591 §1.3) and what the Dynamic OP
 * profile cannot be certified without.
 *
 * Nothing else about the request changes, and that is the point: the same reader of metadata, the same
 * policy, the same refusals, the same `201`. What this mode adds is that nothing authorises, so nothing is
 * read and nothing is refused before the metadata is.
 *
 * A credential presented here is read by nothing and spends nothing: a mode that registers whoever asks has
 * nothing to compare, so whoever holds an initial access token of the controlled mode is neither helped nor
 * charged for presenting it. It reads nothing of the body either, so it puts nothing in front of the members
 * the client sent.
 *
 * What makes it acceptable is not in this class but around it: it is a value of one tenant's policy, closed
 * being the default and the absence of a policy, and no key of a deployment sets it for more than the tenant
 * that names it. The tenant that names it has no real user, and the lifetime its policy gives a client
 * nobody ever used is the shorter of the two it names. The policy that would make this mode acceptable on a
 * tenant with real users, what an anonymous client may ask for and how the name and the logo of a stranger
 * appear to a user, is an open question and is written nowhere else (`docs/10-questions-ouvertes.md`).
 */
final readonly class OpenRegistrationAuthorization implements RegistrationAuthorizationInterface
{
    /**
     * The name a registration policy names this mode by (decision 0009).
     */
    public const string MODE = 'open';

    public function name(): string
    {
        return self::MODE;
    }

    public function authorize(Tenant $tenant, RegistrationRequest $request, ClientRegistrationPolicy $policy): array
    {
        return [];
    }
}
