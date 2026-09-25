<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Device;

use Heidi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;
use function str_contains;
use function urlencode;

/**
 * The successful answer of the device authorization endpoint (RFC 8628 §3.2): what the client polls with,
 * what it shows its user, where that user goes, and for how long. Never cached, both values being
 * credentials of one use.
 *
 * The complete URI of §3.3.1 is written here and not by the caller: it is the verification URI carrying
 * the user code, so that an appliance able to show a link or a QR code sends its user to a page that has
 * the code already. It is one member of this answer and not a second decision.
 */
final readonly class DeviceAuthorizationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 200;

    /**
     * RFC 8628 §3.2, for the errors of §3.2 as well.
     */
    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    /**
     * The query parameter the complete verification URI carries the code in, which is also the field the
     * page reads it from: the appliance sends its user to that URI and the page reads one name.
     */
    public const string USER_CODE_PARAMETER = 'user_code';

    /**
     * @param string $deviceCode what the client polls the token endpoint with (RFC 8628 §3.2)
     * @param UserCode $userCode what it shows its user
     * @param string $verificationUri the page of this provider where the user types the code
     * @param int $expiresIn the seconds both codes still live, at least one
     * @param int $interval the seconds the client waits between two polls, at least one
     *
     * @throws InvalidArgumentException when the answer says nothing a client could use
     */
    public function __construct(
        #[SensitiveParameter]
        public string $deviceCode,
        #[SensitiveParameter]
        public UserCode $userCode,
        public string $verificationUri,
        public int $expiresIn,
        public int $interval,
    ) {
        if ($expiresIn < 1) {
            throw new InvalidArgumentException('A device authorization request is answered with the seconds it still lives, at least one (RFC 8628 section 3.2).');
        }
        if ($interval < 1) {
            throw new InvalidArgumentException('A device authorization request is answered with a polling interval of at least one second (RFC 8628 section 3.2).');
        }
    }

    /**
     * RFC 8628 §3.3.1: the verification URI with the code already in it.
     */
    public function completeVerificationUri(): string
    {
        return (
            $this->verificationUri
            . (str_contains($this->verificationUri, '?') ? '&' : '?')
            . self::USER_CODE_PARAMETER
            . '='
            . urlencode($this->userCode->formatted())
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function parameters(): array
    {
        return [
            'device_code' => $this->deviceCode,
            'user_code' => $this->userCode->formatted(),
            'verification_uri' => $this->verificationUri,
            'verification_uri_complete' => $this->completeVerificationUri(),
            'expires_in' => $this->expiresIn,
            'interval' => $this->interval,
        ];
    }
}
