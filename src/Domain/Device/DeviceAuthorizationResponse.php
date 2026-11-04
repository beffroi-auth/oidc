<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Domain\Device;

use Beffroi\Oidc\Exception\InvalidArgumentException;
use SensitiveParameter;
use function str_contains;
use function urlencode;

/**
 * RFC 8628 §3.2
 */
final readonly class DeviceAuthorizationResponse
{
    public const string CONTENT_TYPE = 'application/json';

    public const int STATUS_CODE = 200;

    public const array HEADERS = [
        'Cache-Control' => 'no-cache, no-store',
        'Pragma' => 'no-cache',
    ];

    public const string USER_CODE_PARAMETER = 'user_code';

    /**
     * @throws InvalidArgumentException
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
     * RFC 8628 §3.3.1
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
