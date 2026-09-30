<?php

declare(strict_types=1);

namespace Heidi\Oidc\Domain\Authorization;

use Heidi\Core\Domain\Algorithm\NamedAlgorithmInterface;
use SensitiveParameter;

/**
 * One transformation a client makes its PKCE challenge with (RFC 7636 §4.2), under the name it answers to
 * in "code_challenge_method" (§4.3) and the name "code_challenge_methods_supported" announces (RFC 8414
 * §2). One class per method, wired into the provider: what the discovery document announces, what an
 * authorization request may name and what a stored challenge is read back as all read that one wired
 * list, and a method the provider gains is a class added to the wiring, never a case added to an
 * enumeration.
 *
 * A method verifies its own challenge, because the transformation and the comparison are one rule (§4.6):
 * what a caller holds is a challenge it cannot compute and a verifier it must not compare itself.
 * "plain", the other transformation of §4.2, is a name no class of this package answers to, decision 0006
 * refusing it.
 */
interface CodeChallengeMethodInterface extends NamedAlgorithmInterface
{
    /**
     * RFC 7636 §4.6: whether the verifier the token endpoint received is the one the challenge was made
     * from, compared in constant time. The syntax of the verifier (§4.1) is the caller's check.
     */
    public function verifies(string $challenge, #[SensitiveParameter] string $codeVerifier): bool;
}
