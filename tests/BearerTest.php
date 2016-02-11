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

namespace SomozaTest\Unit\Psr7\OAuth2Middleware;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Somoza\Psr7\OAuth2Middleware\Bearer;

/**
 * Class BearerTest
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
class BearerTest extends TestCase
{
    /** @var \PHPUnit_Framework_MockObject_MockObject|AbstractProvider */
    private $provider;

    /**
     * setUp
     * @return void
     */
    public function setUp()
    {
        $this->provider = $this->getMockForAbstractClass(
            AbstractProvider::class,
            [],
            '',
            true,
            true,
            true,
            ['getAccessToken']
        );
    }

    /**
     * tearDown
     * @return void
     */
    public function tearDown()
    {
        $this->provider = null;
    }

    /**
     * testConstructorWithoutAccessToken
     * @test
     */
    public function can_construct_without_access_token()
    {
        $instance = new Bearer($this->provider);
        $token = $this->getPropVal($instance, 'accessToken');
        $this->assertNull($token);
    }

    /**
     * testConstructorWithAccessToken
     * @test
     */
    public function can_construct_with_access_token()
    {
        $token = new AccessToken(['access_token' => '123']);
        $instance = new Bearer($this->provider, $token);
        $result = $this->getPropVal($instance, 'accessToken');
        $this->assertSame($token, $result);
    }

    /**
     * testRequestNewAccessToken
     * @test
     */
    public function can_request_new_access_token()
    {
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            //->with('client_credentials')
            ->willReturn('123');

        $instance = new Bearer($this->provider);

        $this->invoke($instance, 'checkAccessToken');

        $this->assertEquals('123', $this->getPropVal($instance, 'accessToken'));
    }

    /**
     * should_skip_requests_with_authentication_header
     * @return void
     *
     * @test
     */
    public function should_skip_requests_with_authentication_header()
    {
        $request = new Request('GET', 'http://foo.bar/oauth', ['Authentication' => null]);
        $instance = new Bearer($this->provider);

        $result = $this->invoke($instance, 'authenticate', [$request]);
        $this->assertSame($request, $result);
    }

    /**
     * should_skip_non_GET_requests
     * @test
     */
    public function should_skip_non_GET_requests()
    {
        $request = new Request('POST', 'http://foo.bar/oauth');
        $instance = new Bearer($this->provider);

        $result = $this->invoke($instance, 'authenticate', [$request]);
        $this->assertSame($request, $result);
    }

    /**
     * should_skip_requests_to_authentication_uri
     * @test
     */
    public function should_skip_requests_to_authentication_uri()
    {
        $this->provider->expects($this->once())
            ->method('getBaseAuthorizationUrl')
            ->willReturn('http://foo.bar/oauth');
        $instance = new Bearer($this->provider);
        $request = new Request('GET', 'http://foo.bar/oauth');

        $result = $this->invoke($instance, 'authenticate', [$request]);
        $this->assertSame($request, $result);
    }

    /**
     * should_request_new_access_token_if_no_token
     * @test
     */
    public function should_request_new_access_token_if_no_token()
    {
        $instance = new Bearer($this->provider);

        $accessToken = new AccessToken(['access_token' => '123']);
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($accessToken);

        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authenticate', [$request]);

        $this->assertResultAuthenticatedWithToken($result, $accessToken);
    }

    /**
 * should_request_new_access_token_if_expired
 * @test
 */
    public function should_request_new_access_token_if_expired()
    {
        $time = time();
        $oldToken = new AccessToken(['access_token' => '123', 'expires' => $time]);
        $newToken = new AccessToken(['access_token' => 'abc']);

        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($newToken);

        $instance = new Bearer($this->provider, $oldToken);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authenticate', [$request]);
        $this->assertResultAuthenticatedWithToken($result, $newToken);
    }

    /**
     * should_not_request_new_access_token_if_token_still_valid
     * @test
     */
    public function should_not_request_new_access_token_if_token_has_no_expiration()
    {
        $validToken = new AccessToken(['access_token' => '123']);

        $this->provider->expects($this->never())
            ->method('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $this->invoke($instance, 'authenticate', [$request]);

        $this->assertResultAuthenticatedWithToken($result, $validToken);
    }

    /**
     * should_not_request_new_access_token_if_token_still_valid
     * @test
     */
    public function should_not_request_new_access_token_if_token_still_valid()
    {
        $time = time() + 3600;
        $validToken = new AccessToken(['access_token' => '123', 'expires' => $time]);

        $this->provider->expects($this->never())
            ->method('getAccessToken');

        $instance = new Bearer($this->provider, $validToken);
        $request = new Request('GET', 'http://foo.bar/baz');
        $result = $this->invoke($instance, 'authenticate', [$request]);

        $this->assertResultAuthenticatedWithToken($result, $validToken);
    }

    /**
     * invoke_should_return_function
     * @test
     */
    public function invoke_should_return_function()
    {
        $callback = function() {};

        $instance = new Bearer($this->provider);
        $this->assertTrue(method_exists($instance, '__invoke'));

        $func = $instance->__invoke($callback);

        $this->assertInternalType('callable', $func);
    }

    /**
     * @test
     */
    public function should_invoke_token_callback_if_token_renewed()
    {
        $accessToken = new AccessToken(['access_token' => '123']);
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($accessToken);
        $tokenCallbackCalled = false;

        // the callback that we're testing
        $tokenCallback = function (AccessToken $token) use (&$tokenCallbackCalled, $accessToken) {
            $tokenCallbackCalled = true;
            $this->assertSame($token, $accessToken);
        };

        $instance = new Bearer($this->provider, null, $tokenCallback);
        $request = new Request('GET', 'http://foo.bar/baz');

        $result = $this->invoke($instance, 'authenticate', [$request]);

        $this->assertResultAuthenticatedWithToken($result, $accessToken);
    }

    /**
     * End-to-end test
     *
     * @test
     */
    public function invoke_function_should_authenticate()
    {
        $callbackCalled = false;
        $callback = function(RequestInterface $request, array $options) use (&$callbackCalled) {
            $callbackCalled = true;
            $this->assertEquals(['foo' => 'bar'], $options);
            $this->assertTrue($request->hasHeader('Authentication'));
            return new Response(); // ok
        };

        $validToken = new AccessToken(['access_token' => 'abc']);
        $this->provider->expects($this->once())
            ->method('getAccessToken')
            ->willReturn($validToken);

        $request = new Request('GET', 'http://foo.bar/baz');
        $options = ['foo' => 'bar'];

        /** @var Bearer|\PHPUnit_Framework_MockObject_MockObject $instance */
        $instance = new Bearer($this->provider);
        $func = $instance->__invoke($callback);

        $func($request, $options);

        $this->assertTrue($callbackCalled);
    }

    /**
     * assertResultAuthenticatedWithToken
     * @param $result
     * @param $accessToken
     * @return void
     */
    private function assertResultAuthenticatedWithToken(RequestInterface $result, AccessToken $accessToken)
    {
        $this->assertTrue($result->hasHeader('Authentication'));
        $this->assertContains('Bearer ' . $accessToken->getToken(), $result->getHeader('Authentication'));
    }
}
