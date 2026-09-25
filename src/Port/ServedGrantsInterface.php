<?php

declare(strict_types=1);

namespace Heidi\Oidc\Port;

use Heidi\Oidc\Domain\Client\GrantTypeName;

/**
 * The grants the token endpoint is wired with (OIDC Discovery §3), the one source of truth over them:
 * what the endpoint serves, what a client may register and what the discovery document announces all
 * read this one, so that they cannot disagree (issue #98).
 */
interface ServedGrantsInterface
{
    /**
     * @return non-empty-list<GrantTypeName> in the order they are wired
     */
    public function servedGrantTypes(): array;

    /**
     * Those of them whose response may carry a refresh token (RFC 6749 §4.1.4).
     *
     * @return list<GrantTypeName>
     */
    public function issuingRefreshTokens(): array;

    /**
     * Those of them that spend a refresh token (RFC 6749 §6).
     *
     * @return list<GrantTypeName>
     */
    public function spendingRefreshTokens(): array;

    /**
     * Those of them a client uses for itself, with nobody signed in behind it (RFC 6749 §4.4).
     *
     * @return list<GrantTypeName>
     */
    public function actingForTheClientItself(): array;

    /**
     * Those of them whose flow sends the user's browser back to the client (RFC 6749 §3.1.2).
     *
     * @return list<GrantTypeName>
     */
    public function sendingTheUserToTheClient(): array;
}
