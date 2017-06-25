<?php

namespace SomozaTest\OAuth2Middleware;

use Assert\InvalidArgumentException;
use GuzzleHttp\Psr7\Request;
use Mockery as m;
use Psr\Http\Message\RequestInterface;
use Somoza\OAuth2Middleware\OAuth2Middleware;
use Somoza\OAuth2Middleware\TokenService\AuthorizesRequests;

/**
 * @author Gabriel Somoza <gabriel@strategery.io>
 */
class OAuth2MiddlewareTest extends TestCase
{
    /** @var AuthorizesRequests|m\Mock */
    private $tokenService;
    private $proxyHandler;

    public function setUp()
    {
        $this->tokenService = m::mock(AuthorizesRequests::class);
        $this->proxyHandler = function ($request) {
            return $request;
        };
    }

    public function testConstructor()
    {
        new OAuth2Middleware($this->tokenService, []);
    }

    public function testConstructorWithInvalidIgnoredUri()
    {
        $this->setExpectedException(InvalidArgumentException::class);
        $invalidIgnoredUris = [123]; // not a string
        new OAuth2Middleware($this->tokenService, $invalidIgnoredUris);
    }

    public function testShouldBehaveLikeMiddleware()
    {
        $instance = new OAuth2Middleware($this->tokenService, []);
        $this->assertTrue(is_callable($instance));

        $middleware = $instance($this->proxyHandler);
        $this->assertTrue(is_callable($middleware));
    }

    public function testShouldSkipsIgnoredUris()
    {
        $instance = new OAuth2Middleware($this->tokenService, ['/skip_uri']);
        $middleware = $instance($this->proxyHandler);
        $request = new Request('GET', '/skip_uri');

        $this->tokenService->shouldNotHaveReceived('authorize');

        $middleware($request, []);
    }

    public function testShouldAuthorizeRequests()
    {
        $instance = new OAuth2Middleware($this->tokenService, ['/skip_uri']);
        $middleware = $instance($this->proxyHandler);
        $request = new Request('GET', '/secured/should_authorize');

        $this->tokenService
            ->shouldReceive('authorize')
            ->with($request)
            ->andReturn($request->withHeader('Authorization', 'Bearer 123'));

        /** @var RequestInterface $response */
        $response = $middleware($request, []);

        $this->assertTrue($response->hasHeader('Authorization'));
        $this->assertEquals('Bearer 123', $response->getHeaderLine('Authorization'));
    }

    public function tearDown()
    {
        parent::tearDown();
        $this->proxyHandler = null;
        $this->tokenService = null;
    }
}
