<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Key;

use DateInterval;
use Heidi\Core\Domain\Key\KeyUse;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\KeyBoundArtifactInterface;
use Heidi\Oidc\Application\Authorization\ResponseDocumentIssuer;
use Heidi\Oidc\Port\ServedResponseModesInterface;

/**
 * The signed authorization response (JARM §2.1, issue #163), issued only where the integration wires a
 * way of delivering one: a deployment that answers in "query" and "form_post" alone signs no such
 * document, and its keys retire on the lifetimes of the tokens. The lifetime is read from the issuer so
 * that the two cannot disagree, which is the rule issue #155 asks of every kind.
 */
final readonly class ResponseDocumentJwsKind implements KeyBoundArtifactInterface
{
    public function __construct(
        private ResponseDocumentIssuer $issuer,
        private ServedResponseModesInterface $responseModes,
    ) {
    }

    public function keyUse(): KeyUse
    {
        return KeyUse::Signature;
    }

    public function longestLifetime(Tenant $tenant): ?DateInterval
    {
        return $this->responseModes->signsAnyAnswer() ? $this->issuer->lifetime : null;
    }
}
