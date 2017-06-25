<?php

namespace Somoza\OAuth2Middleware\TokenService;

use Psr\Http\Message\RequestInterface;

/**
 * @author Gabriel Somoza <gabriel@strategery.io>
 */
interface AuthorizesRequests
{
    /**
     * Checks whether a request is authorized with this service's Access Token.
     *
     * @param RequestInterface $request
     * @return bool
     */
    public function isAuthorized(RequestInterface $request): bool;

    /**
     * Authorizes a request using an OAuth2 Access Token. SHOULD be idempotent.
     *
     * @param RequestInterface $request
     * @return RequestInterface
     */
    public function authorize(RequestInterface $request): RequestInterface;
}
