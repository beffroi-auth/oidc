<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Token;

/**
 * What an access token is bound to (RFC 7800 §3.1): one member of the "cnf" claim of an "at+jwt", of the
 * "cnf" of an introspection response, and of the record of an opaque token. A token that carries none is
 * a bearer token, honoured by whoever holds it.
 *
 * Two kinds today, the certificate the client presented at the handshake (RFC 8705 §3.1) and the key it
 * proved possession of (RFC 9449 §6.1), each one a class that knows the member it is written under, the
 * scheme the token is then presented with, and how it is compared. A third kind is a class added beside
 * them; nothing enumerates them and nothing reads a class name.
 */
interface ConfirmationInterface
{
    /**
     * RFC 7800 §3.1: the claim every confirmation is written under, in an "at+jwt", in an introspection
     * response and in the record of an opaque token.
     */
    public const string CLAIM = 'cnf';

    /**
     * The member of the "cnf" this confirmation is written under (RFC 7800 §3.1).
     *
     * @return non-empty-string
     */
    public function member(): string;

    /**
     * The thumbprint the member carries, base64url without padding, in the shape the class that speaks
     * for that member checked when it was built.
     */
    public function value(): string;

    /**
     * The scheme the token this confirmation binds is presented with, which is also the "token_type" of
     * the response that handed it out (RFC 6749 §5.1): "Bearer" for a token whose holder is checked by
     * the transport (RFC 8705 §3), "DPoP" for one whose holder signs a proof for every request
     * (RFC 9449 §5, §7.1).
     *
     * @return non-empty-string
     */
    public function scheme(): string;

    /**
     * @return array<string, mixed> the "cnf" claim, to merge into the claims of a token or into the
     *                              members of an introspection response
     */
    public function toClaims(): array;

    /**
     * Whether the two name the same thing: the same member, carrying the same thumbprint.
     */
    public function matches(self $other): bool;
}
