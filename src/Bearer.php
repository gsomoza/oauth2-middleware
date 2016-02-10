<?php

namespace Strategery\Psr7\OAuth2Middleware;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;

/**
 * Bearer PSR7 Middleware
 *
 * @author Gabriel Somoza <gabriel@strategery.io>
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
        return function(RequestInterface $request, array $options) use ($handler) {
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
