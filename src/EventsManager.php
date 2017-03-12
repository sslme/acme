<?php
namespace Sslme\Acme;

trait EventsManager
{
	/** @var array $__events */
	private $__events = [];

	/**
	 * @param string $name
	 * @param callable $callback
	 * @return $this
	 */
	public function on($name, $callback)
	{
		if (is_callable($callback)) {
			$this->__events[$name][] = $callback;
		}
		return $this;
	}

	/**
	 * @return bool
	 */
	public function trigger()
	{
		$arguments = func_get_args();
		$name = array_shift($arguments);

		if (isset($this->__events[$name])) {
			foreach ($this->__events[$name] as $handler) {
				if (call_user_func_array($handler, $arguments) === false) {
					return false;
				}
			}
		}
		return true;
	}
}