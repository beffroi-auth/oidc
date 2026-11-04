<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Authorization;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\AuthorizationDetails\AuthorizationDetails;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\ResolvesItsClientInterface;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\KeyConfirmation;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 6749 §4.1.2
 */
final class AuthorizationCode extends GrantRecord implements ResolvesItsClientInterface
{
    public readonly Tenant $tenant;

    public readonly string $clientId;

    /**
     * @param string $codeHash the hex SHA-256 of the code
     * @param CodeChallenge|null $codeChallenge null only for a client that does not require PKCE
     */
    public function __construct(
        public readonly string $codeHash,
        public readonly Uuid $grantId,
        public readonly Client $client,
        public readonly AuthenticationSession $session,
        public readonly RedirectUri $redirectUri,
        public readonly Scopes $scopes,
        public readonly ?ResourceIndicators $resources,
        public readonly ?AuthorizationDetails $authorizationDetails,
        public readonly ?string $nonce,
        public readonly ?CodeChallenge $codeChallenge,
        public readonly ?KeyConfirmation $dpopKey,
        public readonly ?ClaimsRequest $claimsRequest,
        public readonly AuthenticationSnapshot $authentication,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
    ) {
        if (! DrawnSecret::isDigest($codeHash)) {
            throw new InvalidArgumentException('An authorization code is stored as its hex SHA-256.');
        }
        if (! $session->tenant->equals($client->tenant)) {
            throw new InvalidArgumentException('An authorization code binds a session and a client of the same tenant.');
        }
        if ($expiresAt <= $issuedAt) {
            throw new InvalidArgumentException('An authorization code expires after it was issued.');
        }
        $this->tenant = $client->tenant;
        $this->clientId = $client->registration->clientId;
    }

    protected function nameOfRecord(): string
    {
        return 'An authorization code';
    }

    protected function readerThatChecks(): string
    {
        return 'the grant';
    }

    public function clientHolder(): object
    {
        return $this;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'grantId' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'clientId' => new NoPersonalDatum(Reason::A_CLIENT),
            'redirectUri' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'scopes' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'resources' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authorizationDetails' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'nonce' => new NoPersonalDatum(Reason::DRAWN_BY_THE_CLIENT),
            'codeChallenge' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'dpopKey' => new NoPersonalDatum(Reason::WHAT_A_TOKEN_IS_BOUND_TO),
            'claimsRequest' => new NoPersonalDatum(Reason::WHAT_THE_REQUEST_ASKED),
            'authentication' => new NoPersonalDatum(Reason::WHAT_THE_SESSION_PROVED),
            'issuedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'codeHash' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
        ];
    }
}
