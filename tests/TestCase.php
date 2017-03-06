<?php

namespace SomozaTest\OAuth2Middleware;

use Mockery as m;

/**
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
class TestCase extends \PHPUnit_Framework_TestCase
{
    public function tearDown()
    {
        parent::tearDown();
        m::close();
    }

    /**
     * invoke
     * @param $object
     * @param $method
     * @param array $args
     * @return mixed
     */
    protected function invoke($object, $method, array $args = [])
    {
        $m = new \ReflectionMethod($object, $method);
        $m->setAccessible(true);
        return $m->invokeArgs($object, $args);
    }

    /**
     * getPropVal
     * @param $object
     * @param $name
     * @return mixed
     */
    protected function getPropVal($object, $name)
    {
        $prop = new \ReflectionProperty($object, $name);
        $prop->setAccessible(true);
        return $prop->getValue($object);
    }
}
