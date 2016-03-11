## OAuth2 client middleware for league/oauth2-client

[![Build Status](https://travis-ci.org/gsomoza/oauth2-middleware.svg?branch=master)](https://travis-ci.org/gsomoza/oauth2-middleware)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/?branch=master)
[![Latest Stable Version](https://poser.pugx.org/somoza/oauth2-client-middleware/v/stable)](https://packagist.org/packages/somoza/oauth2-client-middleware)

[![License](https://poser.pugx.org/somoza/oauth2-client-middleware/license)](https://packagist.org/packages/somoza/oauth2-client-middleware)
[![Author](https://img.shields.io/badge/author-%40gabriel__somoza-blue.svg)](https://img.shields.io/badge/author-%40gabriel__somoza-blue.svg)

PSR7 middleware that uses league/oauth2-client to authenticate requests with an OAuth2 server.

NOTE: the current version of this middleware only supports the "client_credentials" grant type.

## Installation

```
composer require somoza/oauth2-client-middleware
```

## Usage

The current implementation is tied to Guzzle 6, because its a direct dependency of `league/oauth2-client`.

Using Guzzle:

```php
use Somoza\Psr7\OAuth2Middleware;

$stack = new \GuzzleHttp\HandlerStack();
$stack->setHandler(new CurlHandler());
$client = new \GuzzleHttp\Client(['handler' => $stack]);

// instantiate a provider, see league/oauth2-client docs
$provider = new GenericProvider(
    [
        'clientId' => 'your_client_id',
        'clientSecret' => 'your_client_secret',
        'urlAuthorize' => 'your_authorization_url',
        'urlAccessToken' => 'your_access_token_url',
        'urlResourceOwnerDetails' => 'your_resource_owner_url', 
    ], 
    [ 'httpClient' => $client ] // or don't pass it and let the oauth2-client create its own Guzzle client
);

// attach our oauth2 middleware
$oauth2 = new OAuth2Middleware\Bearer($provider);
$stack->push($oauth2);

// if you want to debug, it might be useful to attach a PSR7 logger here
```

## Caching the Access Token

A callback can be assigned to the middleware in order to save the access token for future use. Make sure you know about
the security implications of storing an access token (do it at your own risk).

Example:

```php
use Somoza\Psr7\OAuth2Middleware;
use League\OAuth2\Client\Token\AccessToken;

// see previous example for initialization
$tokenStore = new EncryptedCache(); // you can use whatever you want here
$token = null;
if ($tokenStore->contains($userId)) {
    $tokenData = json_decode($cache->fetch($userId));
    $token = new AccessToken($tokenData);
}

$oauth2 = new OAuth2Middleware\Bearer(
    $provider, 
    $token, // null if nothing was stored - an instance of AccessToken otherwise 
    function(AccessToken $newToken) use ($tokenStore, $userId) {
        // called whenever a new AccessToken is fetched
        $tokenStore->save($userId, $newToken->jsonSerialize());
    }
);

$stack->push($oauth2);
```

## License

MIT - see LICENSE.md
