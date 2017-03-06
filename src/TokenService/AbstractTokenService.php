<?php

namespace Somoza\OAuth2Middleware\TokenService;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;

/**
 * @author Gabriel Somoza <gabriel@strategery.io>
 */
abstract class AbstractTokenService implements AuthorizesRequests
{
    /** @string Refresh Token grant */
    const GRANT_REFRESH_TOKEN = 'refresh_token';

    /** @string */
    const GRANT_CLIENT_CREDENTIALS = 'client_credentials';

    /** @var AbstractProvider */
    private $provider;

    /** @var AccessToken */
    private $accessToken;

    /** @var callable */
    private $refreshTokenCallback;

    /**
     * @param AbstractProvider $provider A League OAuth2 Client Provider.
     * @param null|AccessToken $accessToken Provide an initial (e.g. cached/persisted) access token.
     * @param null|callable $refreshTokenCallback Will be called with a new AccessToken as a parameter if the Access
     *                                            Token ever needs to be renewed.
     */
    public function __construct(
        AbstractProvider $provider,
        AccessToken $accessToken = null,
        callable $refreshTokenCallback = null
    ) {
        if (null === $accessToken) {
            // an empty token that already expired, will trigger a request for a new token
            $accessToken = new AccessToken([
                'access_token' => '123',
                'expires' => time() - 300 // expired 5 minutes ago
            ]);
        }
        $this->accessToken = $accessToken;

        $this->provider = $provider;
        $this->refreshTokenCallback = $refreshTokenCallback;
    }

    /**
     * @inheritdoc
     */
    final public function authorize(RequestInterface $request): RequestInterface
    {
        if (!$this->isAuthorized($request)) {
            try {
                $hasExpired = $this->getAccessToken()->hasExpired();
            } catch (\RuntimeException $e) {
                $hasExpired = false; // token has no "expires" data, so we assume it hasn't expired
            }

            if ($hasExpired) {
                $this->refreshToken();
            }

            $request = $this->getAuthorizedRequest($request);
        }

        return $request;
    }

    /**
     * @return AccessToken
     */
    final protected function getAccessToken(): AccessToken
    {
        return $this->accessToken;
    }

    /**
     * Refreshes an existing Access Token. Or requests a new one (using the client_credentials grant) if no token
     * is available to the service yet.
     *
     * @return void
     */
    final protected function refreshToken()
    {
        $oldAccessToken = $this->accessToken;

        if ($this->accessToken->getRefreshToken()) {
            $this->accessToken = $this->provider->getAccessToken(self::GRANT_REFRESH_TOKEN, [
                'refresh_token' => $this->accessToken->getRefreshToken(),
            ]);
        } else {
            // request a completely new access token
            $this->accessToken = $this->requestAccessToken();
        }

        if ($this->refreshTokenCallback) {
            call_user_func($this->refreshTokenCallback, $this->accessToken, $oldAccessToken);
        }
    }

    /**
     * Request a new Access Token from the provider
     *
     * @return AccessToken
     */
    abstract protected function requestAccessToken(): AccessToken;

    /**
     * Returns an authorized copy of the request. Only gets called when necessary (i.e. not if the request is already
     * authorized), and always with a valid (fresh) Access Token. However, it SHOULD be idempotent.
     *
     * @param RequestInterface $request An unauthorized request
     *
     * @return RequestInterface An authorized copy of the request
     */
    abstract protected function getAuthorizedRequest(RequestInterface $request): RequestInterface;

    /**
     * @return AbstractProvider
     */
    final protected function getProvider(): AbstractProvider
    {
        return $this->provider;
    }
}
