<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Port;

use Beffroi\Oidc\Domain\Client\GrantTypeName;

interface ServedGrantsInterface
{
    /**
     * @return non-empty-list<GrantTypeName>
     */
    public function servedGrantTypes(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function issuingRefreshTokens(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function spendingRefreshTokens(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function actingForTheClientItself(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function requiringClientAuthentication(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function sendingTheUserToTheClient(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function askingTheUserOnAnotherDevice(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function askingTheUserThroughABackchannel(): array;

    /**
     * @return list<GrantTypeName>
     */
    public function exchangingTokens(): array;
}
