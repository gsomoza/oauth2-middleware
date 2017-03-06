<?php

namespace SomozaTest\Unit\Psr7\OAuth2Middleware;

use GuzzleHttp\Psr7\Request;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Mockery as m;
use Psr\Http\Message\RequestInterface;
use Somoza\OAuth2Middleware\TokenService\AbstractTokenService;
use Somoza\OAuth2Middleware\TokenService\Bearer;
use SomozaTest\OAuth2Middleware\TestCase;

/**
 * Class BearerTest
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
class BearerTest extends TestCase
{
    /** @var AbstractProvider|m\Mock */
    private $provider;

    /**
     * setUp
     * @return void
     */
    public function setUp()
    {
        $this->provider = m::mock(AbstractProvider::class);
    }

    public function testConstructorWithoutAccessToken()
    {
        $instance = new Bearer($this->provider);

        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that a dummy token was created
        $token = $method->invoke($instance);
        $this->assertInstanceOf(AccessToken::class, $token);
        /** @var AccessToken $token */
        $this->assertTrue($token->hasExpired());
    }

    public function testConstructorWithAccessToken()
    {
        $token = new AccessToken(['access_token' => '123']);
        $instance = new Bearer($this->provider, $token);
        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that a dummy token was created
        $result = $method->invoke($instance);

        $this->assertSame($token, $result);
    }

    public function testShouldRequestNewAccessTokenIfNoToken()
    {
        $accessToken = m::mock(AccessToken::class, ['getToken' => 'abc']);
        $this->provider->shouldReceive('getAccessToken')
            ->once()
            ->with('client_credentials')
            ->andReturn($accessToken);

        $instance = new Bearer($this->provider); // with an expired token

        $request = new Request('GET', '/secured/resource');
        $instance->authorize($request);

        $method = new \ReflectionMethod(AbstractTokenService::class, 'getAccessToken');
        $method->setAccessible(true);

        // test that the token was returned
        $result = $method->invoke($instance);

        $this->assertSame($accessToken, $result);
    }

    /**
     * should_skip_requests_with_authorization_header
     * @return void
     *
     * @test
     */
    public function testShouldSkipAuthorizedRequests()
    {
        $instance = new Bearer($this->provider); // with an expired token
        $request = new Request('GET', '/secured/resource', ['Authorization' => 'Bearer 123']);

        $result = $instance->authorize($request);

        $this->assertSame($request, $result);
        $this->provider->shouldNotHaveReceived('getAccessToken');
    }

    public function testShouldRefreshTokenIfExpired()
    {
        $pastTime = time() - 500;
        $oldToken = new AccessToken(['access_token' => '123', 'expires' => $pastTime, 'refresh_token' => 'xyz',]);
        $newToken = new AccessToken(['access_token' => 'abc']);

        $this->provider
            ->shouldReceive('getAccessToken')
            ->once()
            ->with('refresh_token', ['refresh_token' => 'xyz'])
            ->andReturn($newToken);

        $instance = new Bearer($this->provider, $oldToken);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $instance->authorize($request);

        //$result = $this->invoke($instance, 'authorizeRequest', [$request]);
        $this->assertResultAuthorizedWithToken($result, $newToken);
    }

    /**
     * @param RequestInterface $result
     * @param AccessToken $accessToken
     * @return void
     */
    private function assertResultAuthorizedWithToken(RequestInterface $result, AccessToken $accessToken)
    {
        $this->assertTrue($result->hasHeader(Bearer::HEADER_AUTHORIZATION));
        $this->assertContains(Bearer::TOKEN_TYPE . ' ' . $accessToken->getToken(),
            $result->getHeader(Bearer::HEADER_AUTHORIZATION));
    }

    public function testShouldNotRequestNewAccessTokenIfTokenHasNoExpiration()
    {
        $validToken = new AccessToken(['access_token' => '123']);

        $this->provider->shouldNotReceive('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $instance->authorize($request);

        $this->assertResultAuthorizedWithToken($result, $validToken);
    }

    public function testShouldNotRefreshTokenIfStillValid()
    {
        $validToken = new AccessToken(['access_token' => '123', 'expires_in' => 300]);

        $this->provider->shouldNotReceive('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $instance->authorize($request);

        $this->assertResultAuthorizedWithToken($result, $validToken);
    }

    public function testShouldInvokeCallbackIfTokenRenewed()
    {
        $oldToken = new AccessToken(['access_token' => 'oldie', 'expires' => time() - 300]);
        $newToken = new AccessToken(['access_token' => '123']);
        $this->provider->shouldReceive('getAccessToken')
            ->once()
            ->andReturn($newToken);

        // the callback that we're testing
        $callbackCalled = false;
        $tokenCallback = function (AccessToken $newTokenActual, AccessToken $oldTokenActual = null)
        use ($newToken, $oldToken, &$callbackCalled) {
            $callbackCalled = true;
            $this->assertSame($newTokenActual, $newToken);
            $this->assertSame($oldToken, $oldTokenActual);
        };

        $instance = new Bearer($this->provider, $oldToken, $tokenCallback);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $instance->authorize($request);

        $this->assertTrue($callbackCalled);
        $this->assertResultAuthorizedWithToken($result, $newToken);
    }
}
