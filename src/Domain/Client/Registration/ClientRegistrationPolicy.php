<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Exception\InvalidArgumentException;

/**
 * What a tenant does with a client that registers itself (RFC 7591, decision 0009). A tenant that has no
 * policy registers nobody: closed is the default, and it is the absence of a policy and not a mode of
 * one, which is why a closed tenant has no registration endpoint at all rather than one that refuses
 * what it has read.
 *
 * The mode is a name and never a case: what authorises a registration is a class that names itself the
 * same way (`RegistrationAuthorizationInterface`), read among those the deployment wired, so that a mode
 * the provider gains is a class added and a line of wiring. A policy that names a mode nothing serves is
 * a deployment that wired one thing and wrote another, and it is told so.
 *
 * The PKCE exemption is decision 0017: the rule of 0006 stands, and a tenant may write the exception of
 * 0008 on the confidential clients its policy registers, never on a public one. It is a field of this
 * policy and of nothing global, it is written on a registration at the moment the policy creates it, and
 * nothing a client sends grants it.
 */
final readonly class ClientRegistrationPolicy
{
    /**
     * @param string $mode what authorises a registration here, under the name the class that is that mode gives itself (decision 0009); never empty, a tenant that authorises nothing having no policy at all
     * @param bool $exemptsConfidentialClientsFromPkce whether the confidential clients this policy registers are registered without the PKCE requirement (decision 0017); a public client is never exempted, whatever this carries
     *
     * @throws InvalidArgumentException when the policy names no mode
     */
    public function __construct(
        public string $mode,
        public bool $exemptsConfidentialClientsFromPkce = false,
    ) {
        if ($mode === '') {
            throw new InvalidArgumentException('A registration policy names what authorises a registration (decision 0009); a tenant that authorises none has no policy at all.');
        }
    }

    /**
     * What this policy writes on a registration it creates, under the members the reader of a
     * registration reads (decision 0017): read from the policy every time the policy writes a
     * registration, at the creation of RFC 7591 §3.1 as at the replacement of RFC 7592 §2.2, and read
     * from nothing else afterwards.
     *
     * A public client is never exempted (RFC 9700 §2.1.1): it proves nothing at the token endpoint, so
     * the code it spends is bound to it by the verifier and by nothing else. Its registration is not
     * refused for that, since it asked for nothing.
     *
     * @return array<string, mixed>
     */
    public function membersWrittenOn(ClientAuthenticationMethodInterface $method): array
    {
        if (! $this->exemptsConfidentialClientsFromPkce || ! $method->authenticatesClient()) {
            return [];
        }

        return [
            'requires_pkce' => false,
        ];
    }
}
