<?php
namespace Sslme\Acme;

class Certificate
{
	/** @var null|string $name  */
	private $name = null;

	/** @var null|string $content */
	private $content = null;

	/**
	 * Certificate constructor.
	 * @param $name
	 * @param $content
	 */
	public function __construct($name, $content)
	{
		$this->setName($name);
		$this->setContent($content);
	}

	/**
	 * @return null|string
	 */
	public function getName()
	{
		return $this->name;
	}

	/**
	 * @return null|string
	 */
	public function getContent()
	{
		return $this->content;
	}

	/**
	 * @param null|string $name
	 */
	public function setName($name)
	{
		$this->name = $name;
	}

	/**
	 * @param null|string $content
	 */
	public function setContent($content)
	{
		$this->content = $content;
	}

	/**
	 * @param $path
	 * @return int
	 */
	public function saveTo($path)
	{
		return file_put_contents($path, $this->getContent());
	}
}