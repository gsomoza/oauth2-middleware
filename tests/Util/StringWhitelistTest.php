<?php

namespace SomozaTest\Unit\Psr7\OAuth2Middleware\Util;

use Somoza\Psr7\OAuth2Middleware\Util\StringWhitelist;
use Somoza\Psr7\OAuth2Middleware\Util\Whitelist;
use SomozaTest\Unit\Psr7\OAuth2Middleware\TestCase;

/**
 * Class StringWhitelistTest
 *
 * @author Gabriel Somoza <gabriel.somoza@cu.be>
 * @author Pavel Dubinin (@geekdevs)
 */
class StringWhitelistTest extends TestCase
{
    /**
     * @test
     */
    public function implements_interface()
    {
        $whitelist = new StringWhitelist();
        $this->assertInstanceOf(Whitelist::class, $whitelist);
    }

    /**
     * @test
     */
    public function should_add()
    {
        $whitelist = new StringWhitelist();
        $this->assertFalse($whitelist->allowed('test'));
        $whitelist->add('test');
        $this->assertTrue($whitelist->allowed('test'));
    }

    /**
     * @test
     */
    public function should_delete_single_items()
    {
        $whitelist = new StringWhitelist([
            'test',
            'foobar'
        ]);
        $this->assertTrue($whitelist->allowed('test'));
        $whitelist->remove('test');
        $this->assertFalse($whitelist->allowed('test'));
        $this->assertTrue($whitelist->allowed('foobar'));
    }
}
