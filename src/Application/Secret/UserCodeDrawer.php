<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Application\Secret;

use Beffroi\Core\Port\RandomnessInterface;
use Beffroi\Oidc\Domain\Device\UserCode;
use function ord;
use function str_split;
use function strlen;

/**
 * Draws the code an appliance shows its user (RFC 8628 §3.3), beside the drawer of every other value this
 * provider hands out. It is not one of those: a value read out loud and typed on a phone cannot be 256
 * bits of base64url, so it has an alphabet and a length of its own (UserCode) and this is the one place
 * that spells one.
 *
 * The bytes come from where every secret of this provider comes from (RandomnessInterface), so a test
 * fixes what a code will be and reads it back. A byte picks a character only when it falls in the largest
 * whole number of alphabets it can name; the others are dropped rather than folded, because folding 256
 * over twenty would make four characters of the alphabet likelier than the rest and the entropy of the
 * code is exactly what RFC 8628 §5.1 is about.
 */
final readonly class UserCodeDrawer
{
    /**
     * Twelve alphabets of twenty characters: a byte at or above this names nothing and is dropped.
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
