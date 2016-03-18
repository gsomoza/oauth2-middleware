<?php

namespace Somoza\Psr7\OAuth2Middleware\Util;

/**
 * Class StringWhitelist
 *
 * @author Gabriel Somoza <gabriel@somoza.me>
 * @author Pavel Dubinin (@geekdevs)
 */
final class StringWhitelist implements Whitelist
{
    /** @var array */
    private $items = [];

    /**
     * StringWhitelist constructor.
     * @param array $items
     */
    public function __construct(array $items = [])
    {
        $this->items = $items;
    }

    /**
     * Adds a URL to the whitelist
     * @param string $value
     * @return void
     */
    public function add($value)
    {
        $value = (string) $value;
        if (!in_array($value, $this->items)) {
            $this->items[] = $value;
        }
    }

    /**
     * Removes a value from the whitelist
     * @param string $value
     * @return void
     */
    public function remove($value)
    {
        $value = (string) $value;
        if (($key = array_search($value, $this->items)) !== false) {
            unset($this->items[$key]);
        }
    }

    /**
     * allowed
     * @param string $item
     * @return bool
     */
    public function allowed($item)
    {
        $item = (string) $item;
        return in_array($item, $this->items);
    }
}
