<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Client\Registration;

use function array_find;
use DateInterval;
use DateTimeImmutable;
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
 *
 * The authorities whose software statements it accepts are the tenant's and are written here (RFC 7591
 * §2.3, `StatementIssuer`): the attested mode reads them, and a tenant that pins none has that mode
 * closed rather than open to whoever signs. They are a field of this policy and of nothing global, for
 * the same reason the mode is: what one tenant trusts is unknown to another.
 *
 * The two durations are the hygiene decision 0009 makes part of itself: a client nobody uses any more is
 * deleted, and a tenant says after how long. They are two because a client that was used and a client that
 * never was are not worth the same, and the mode that registers strangers makes the second the shorter of
 * the two.
 */
final readonly class ClientRegistrationPolicy
{
    /**
     * Ninety days, which is the absolute lifetime of a refresh token family this provider is configured
     * with by default (`refresh_token_absolute_ttl`): past it, nothing this client was ever issued can
     * still be presented, so deleting it takes nothing away from anybody.
     */
    public const string UNUSED_FOR = 'P90D';

    /**
     * Seven days, a working week, so that a registration made on a Friday afternoon is still there the
     * next Friday. A client that was never used holds nothing at all, so the only question this answers is
     * how long whoever registered it may take to make its first request.
     */
    public const string NEVER_USED_FOR = 'P7D';

    /**
     * @param string $mode what authorises a registration here, under the name the class that is that mode gives itself (decision 0009); never empty, a tenant that authorises nothing having no policy at all
     * @param bool $exemptsConfidentialClientsFromPkce whether the confidential clients this policy registers are registered without the PKCE requirement (decision 0017); a public client is never exempted, whatever this carries
     * @param DateInterval $keepsAClientUnusedFor how long a client that was used may go without being used again before it is deleted
     * @param DateInterval $keepsAClientNeverUsedFor how long a client that was never used lives at all, which the open mode makes the shorter of the two
     * @param list<StatementIssuer> $statementIssuers the authorities whose software statements this tenant accepts (RFC 7591 §2.3); none for a tenant that pins nobody, which is every tenant that wrote none
     *
     * @throws InvalidArgumentException when the policy names no mode
     */
    public function __construct(
        public string $mode,
        public bool $exemptsConfidentialClientsFromPkce = false,
        public DateInterval $keepsAClientUnusedFor = new DateInterval(self::UNUSED_FOR),
        public DateInterval $keepsAClientNeverUsedFor = new DateInterval(self::NEVER_USED_FOR),
        public array $statementIssuers = [],
    ) {
        if ($mode === '') {
            throw new InvalidArgumentException('A registration policy names what authorises a registration (decision 0009); a tenant that authorises none has no policy at all.');
        }
    }

    /**
     * The authority a statement names, among the ones this tenant pinned, or null when it pinned nobody by
     * that name (RFC 7591 §2.3). The name is compared byte for byte, and which key would verify a
     * statement is this answer and never the statement's.
     */
    public function trusts(string $issuer): ?StatementIssuer
    {
        return array_find($this->statementIssuers, static fn (StatementIssuer $pinned): bool => $pinned->issuer === $issuer);
    }

    /**
     * What this tenant still keeps at that instant (decision 0009), as two dates a store can ask its rows.
     */
    public function retentionAt(DateTimeImmutable $now): ClientRetention
    {
        return new ClientRetention($now->sub($this->keepsAClientUnusedFor), $now->sub($this->keepsAClientNeverUsedFor));
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
