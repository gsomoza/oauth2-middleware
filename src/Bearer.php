<?php
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Gabriel Somoza
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace Somoza\Psr7\OAuth2Middleware;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;

/**
 * Bearer PSR7 Middleware
 *
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
final class Bearer
{
    const HEADER_AUTHENTICATION = 'Authentication';

    const AUTHENTICATION_SCHEMA = 'Bearer';

    /** @var AbstractProvider */
    private $provider;

    /** @var AccessToken */
    private $accessToken;

    /**
     * OAuth2Middleware constructor.
     * @param AccessToken $accessToken
     * @param AbstractProvider $provider
     */
    public function __construct(
        AbstractProvider $provider,
        AccessToken $accessToken = null
    ) {
        $this->provider = $provider;
        $this->accessToken = $accessToken;
    }

    /**
     * __invoke
     * @param callable $handler
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            $request = $this->authenticate($request);
            return $handler($request, $options);
        };
    }

    /**
     * Authenticate
     * @param RequestInterface $request
     * @return RequestInterface
     */
    protected function authenticate(RequestInterface $request)
    {
        if ($request->getMethod() !== 'GET'
            || $request->hasHeader('Authentication')
            || $request->getUri() == $this->provider->getBaseAuthorizationUrl()
        ) {
            return $request;
        }

        $this->checkAccessToken();

        return $request->withHeader(
            self::HEADER_AUTHENTICATION,
            self::AUTHENTICATION_SCHEMA . ' ' . $this->accessToken->getToken()
        );
    }

    /**
     * checkAccessToken
     * @return AccessToken
     */
    private function checkAccessToken()
    {
        $now = time();
        if (!$this->accessToken
            || ($this->accessToken->getExpires() !== null
                && $this->accessToken->getExpires() - $now <= 0)
        ) {
            $this->accessToken = $this->provider->getAccessToken('client_credentials');
        }
    }
}
