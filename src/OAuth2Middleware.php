<?php

namespace Somoza\OAuth2Middleware;

use Assert\Assertion;
use Psr\Http\Message\RequestInterface;
use Somoza\OAuth2Middleware\TokenService\AuthorizesRequests;

/**
 * @author Gabriel Somoza <gabriel@strategery.io>
 */
final class OAuth2Middleware
{
    /** @var AuthorizesRequests */
    private $tokenService;

    /** @var string[] */
    private $ignoredUris;

    /**
     * Middleware constructor.
     * @param AuthorizesRequests $tokenService
     * @param \string[] $ignoredUris
     */
    public function __construct(AuthorizesRequests $tokenService, array $ignoredUris = [])
    {
        Assertion::allString($ignoredUris);
        $this->ignoredUris = $ignoredUris;
        $this->tokenService = $tokenService;
    }


    /**
     * @param callable $handler
     * @return \Closure
     */
    public function __invoke(callable $handler): \Closure
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            $uri = (string) $request->getUri();
            if (!$this->shouldSkipAuthorizationForUri($uri)) {
                $request = $this->tokenService->authorize($request);
            }

            return $handler($request, $options);
        };
    }

    /**
     * Returns whether a URL must NOT be authorized
     *
     * @param string $uri
     * @return bool
     */
    private function shouldSkipAuthorizationForUri(string $uri): bool
    {
        return in_array($uri, $this->ignoredUris);
    }
}
