<?php
namespace Sslme\Acme;

class CertificatesCollection
{
	use EventsManager;

	/** @var Certificate[] $certificates */
	private $certificates = [];

	/**
	 * CertificatesCollection constructor.
	 * @param array $certificates
	 */
	public function __construct($certificates = [])
	{
		$this->certificates = $certificates;
	}

	/**
	 * @param Certificate $certificate
	 * @return $this
	 */
	public function add(Certificate $certificate)
	{
		$this->certificates[$certificate->getName()] = $certificate;

		$this->trigger('generated:certificate', $certificate);
		return $this;
	}

	/**
	 * @return Certificate[]
	 */
	public function getCertificates()
	{
		return $this->certificates;
	}

	/**
	 * @param string $name
	 * @return Certificate
	 */
	public function get($name)
	{
		return $this->certificates[$name];
	}
}