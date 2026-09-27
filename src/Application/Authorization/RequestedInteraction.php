<?php

declare(strict_types=1);

namespace Heidi\Oidc\Application\Authorization;

use function count;
use function explode;
use Heidi\Oidc\Application\Request\RequestParameters;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\Display;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\InvalidRequestException;
use function in_array;
use function preg_match;

/**
 * What an authorization request asks of the pages the user will see (OIDC Core §3.1.2.1): whether to ask
 * again or not to ask at all, how old a sign-in may be, who is expected, in which language, at which
 * authentication context class, on which kind of screen, and what the client wants to know about the
 * person. Eight parameters, one rule each, and none of them a condition the provider must meet: they say
 * what is asked, and the interaction says what happened (§4.3).
 *
 * They are read together because they are decided together, by the handler that turns them into a login,
 * a step-up, a consent or a code; the request keeps each of them on its own, so nothing here is a second
 * copy of what AuthorizationRequest carries.
 */
final readonly class RequestedInteraction
{
    /**
     * OIDC Core §3.1.2.1: seconds, bounded to a PHP integer.
     */
    private const string MAX_AGE_PATTERN = '/^(?:0|[1-9][0-9]{0,17})$/D';

    /**
     * @param list<Prompt> $prompts
     * @param list<string> $uiLocales most preferred first
     * @param list<string> $acrValues in order of preference
     * @param string|null $idTokenHint a compact JWS, verified by the interaction
     */
    private function __construct(
        public array $prompts,
        public ?int $maxAge,
        public ?string $loginHint,
        public array $uiLocales,
        public array $acrValues,
        public ?Display $display,
        public ?string $idTokenHint,
        public ?ClaimsRequest $claims,
    ) {
    }

    /**
     * @throws InvalidRequestException when one of them is not what it must be
     */
    public static function of(RequestParameters $request): self
    {
        return new self(
            self::prompts($request->optional('prompt')),
            self::maxAge($request->optional('max_age')),
            $request->text('login_hint'),
            $request->uiLocales(),
            $request->acrValues(),
            self::display($request->optional('display')),
            $request->compactJws('id_token_hint'),
            self::claims($request->optional('claims')),
        );
    }

    /**
     * OIDC Core §3.1.2.1 "prompt": a closed list, "none" alone.
     *
     * @return list<Prompt>
     */
    private static function prompts(?string $prompt): array
    {
        if ($prompt === null) {
            return [];
        }
        $prompts = [];
        foreach (explode(' ', $prompt) as $value) {
            $candidate = Prompt::tryFrom($value);
            if ($candidate === null) {
                throw new InvalidRequestException('The prompt parameter is not a space-separated list of none, login, consent or select_account.', true);
            }
            if (! in_array($candidate, $prompts, true)) {
                $prompts[] = $candidate;
            }
        }
        if (in_array(Prompt::None, $prompts, true) && count($prompts) > 1) {
            throw new InvalidRequestException('The prompt value none cannot be combined with another value (OIDC Core section 3.1.2.1).', true);
        }

        return $prompts;
    }

    private static function maxAge(?string $maxAge): ?int
    {
        if ($maxAge === null) {
            return null;
        }
        if (preg_match(self::MAX_AGE_PATTERN, $maxAge) !== 1) {
            throw new InvalidRequestException('The max_age parameter must be a non-negative integer.', true);
        }

        return (int) $maxAge;
    }

    private static function display(?string $display): ?Display
    {
        if ($display === null) {
            return null;
        }

        return Display::tryFrom($display) ?? throw new InvalidRequestException('The display parameter is not one of page, popup, touch or wap.', true);
    }

    private static function claims(?string $claims): ?ClaimsRequest
    {
        if ($claims === null) {
            return null;
        }
        try {
            return ClaimsRequest::fromJson($claims);
        } catch (InvalidArgumentException) {
            throw new InvalidRequestException('The claims parameter is not a claims request (OIDC Core section 5.5).', true);
        }
    }
}
