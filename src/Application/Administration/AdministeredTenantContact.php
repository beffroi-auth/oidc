<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Administration;

use Beffroi\Core\Application\Tenant\TenantContactAdoption;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\TenantContact;
use Beffroi\Oidc\Domain\Administration\ActingAdministrator;

/**
 * The contact the tenant gives its people in what tells them of a change to their account, set or taken back by an
 * administrator through the administration API (decision 0038): the act names the administrator.
 */
final readonly class AdministeredTenantContact
{
    public function __construct(
        private TenantContactAdoption $adoption,
    ) {
    }

    public function adopt(ActingAdministrator $administrator, ?TenantContact $contact, RequestContext $context): ?TenantContact
    {
        $this->adoption->adoptByAnAdministrator($administrator->tenant, $contact, $administrator->user->subject, $context);

        return $administrator->tenant->contact;
    }
}
