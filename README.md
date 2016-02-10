## OAuth2 client middleware for league/oauth2-client

[![Build Status](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/badges/build.png?b=master)](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/build-status/master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/gabrielsomoza/oauth2-middleware/?branch=master)

PSR7 middleware that uses league/oauth2-client to authenticate requests with an OAuth2 server

## Installation

```
composer require strategery/oauth2-client-middleware
```

## Usage

The current implementation is tied to Guzzle 6, because its a direct dependency of `league/oauth2-client`.

Using Guzzle:

```php
use Strategery\Psr7\OAuth2Middleware;

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

## License

MIT - see LICENSE.md
