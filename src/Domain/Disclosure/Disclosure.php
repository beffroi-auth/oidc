<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Disclosure;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * What a client was given of a person, at one act of the protocol (issue #590): one row per act that
 * handed something over, so that the question a person asks of their own register, which data did this
 * application obtain of me on 3 March, has an answer.
 *
 * **It is not the journal.** A row of the journal is four facts and two names and no bag a caller fills,
 * because that is the door a secret eventually walks through. So the journal keeps saying that the act
 * happened (`TokensIssued`) and this says what left with it, which is the shape `ClaimChange` has for what
 * a person changed of their own record.
 *
 * **It is not the consent either.** A consent says what a client **may** obtain and answers for its own
 * current state; it goes away when it is taken back, and the grants that carried the scopes go with the
 * revocation and the expiry. This says what a client **did** obtain, at a moment, and it stays for the
 * duration of the journal whatever is taken back afterwards.
 *
 * **What it holds of a request is sealed, where a consent holds the same values in the clear**, and the
 * difference is what the two rows are: a consent is a permission, one row per client, that a dump gives
 * away as a list of permissions, where this is one row per act and a dump of it is what an application
 * obtained of somebody, day by day. That the obtaining happened is in the journal in the clear, as the act
 * of it; what was obtained is here, sealed under the data key of the tenant in a family of its own
 * (decisions 0011 and 0018).
 *
 * **The person is named as the journal names them**, by the subject their account carries and never by a
 * row of that account: the two tables answer one question together and are read by the same name, and an
 * act whose row is gone, or a row whose act is gone, is half an answer, which is why the duration is the
 * journal's.
 *
 * **The identifier is a UUIDv7**, so a register sorts chronologically by its primary key and the last
 * disclosures of a person are a lookup rather than a sort.
 */
final class Disclosure
{
    /**
     * @param string $act the act this belongs to, by the name the event gave itself
     * @param Scopes $scopes what the client was given of that person at that act
     * @param ClaimsRequest|null $claims what it had asked for by name (OIDC Core §5.5), null when it asked for none
     * @param AuthorizationDetails|null $details what it was given beyond the scopes (RFC 9396 §7), null when it was given none
     * @param string $tokenShape the shape the access token was written in (architecture §4.6), as the shape names itself
     *
     * @throws InvalidArgumentException when the row does not say what left, or of whom
     */
    public function __construct(
        public private(set) Uuid $id,
        public readonly Tenant $tenant,
        public readonly Subject $subject,
        public readonly string $clientId,
        public readonly string $act,
        public readonly DateTimeImmutable $handedOverAt,
        public readonly Scopes $scopes,
        public readonly ?ClaimsRequest $claims,
        public readonly ?AuthorizationDetails $details,
        public readonly string $tokenShape,
    ) {
        if ($clientId === '') {
            throw new InvalidArgumentException('What a client was given names the client.');
        }
        if ($act === '') {
            throw new InvalidArgumentException('What a client was given names the act it left with.');
        }
        if ($tokenShape === '') {
            throw new InvalidArgumentException('What a client was given names the shape the access token was written in.');
        }
    }
}
