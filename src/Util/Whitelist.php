<?php

namespace Somoza\Psr7\OAuth2Middleware\Util;

/**
 * Interface Whitelist
 * @author Gabriel Somoza <gabriel@somoza.me>
 */
interface Whitelist
{
    /**
     * Allowed
     * @param $item
     * @return bool
     */
    public function allowed($item);
}
