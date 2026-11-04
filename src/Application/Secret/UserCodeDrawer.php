<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Secret;

use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Oidc\Domain\Device\UserCode;
use function ord;
use function str_split;
use function strlen;

/**
 * RFC 8628 §3.3
 */
final readonly class UserCodeDrawer
{
    /**
     * Twelve alphabets of twenty: a byte at or above it is dropped, as folding it would bias the code (RFC 8628 §5.1).
     */
    private const int CEILING = 240;

    public function __construct(
        private RandomnessInterface $randomness,
    ) {
    }

    public function draw(): UserCode
    {
        $characters = '';
        while (strlen($characters) < UserCode::LENGTH) {
            foreach (str_split($this->randomness->bytes(UserCode::LENGTH)) as $byte) {
                $index = ord($byte);
                if ($index >= self::CEILING) {
                    continue;
                }
                $characters .= UserCode::ALPHABET[$index % strlen(UserCode::ALPHABET)];
                if (strlen($characters) === UserCode::LENGTH) {
                    break;
                }
            }
        }

        return UserCode::of($characters);
    }
}
