<?php
namespace Sslme\Acme;

use Exception;

class DomainsCollection
{
	use EventsManager;

	/** @var Domain[] $domains  */
	private $domains = [];

	/** @var AcmeClient $acme */
	private $acme;

	/**
	 * DomainsCollection constructor.
	 * @param array $domains
	 */
	public function __construct($domains = [])
	{
		$this->domains = $domains;
	}

	/**
	 * @param AcmeClient $acme
	 * @return AcmeClient
	 */
	public function setAcme(AcmeClient $acme)
	{
		return $this->acme = $acme;
	}

	/**
	 * @param Domain $domain
	 */
	public function add(Domain $domain)
	{
		$domain->setAcme($this->acme);
		$this->domains[$domain->toString()] = $domain;
	}

	/**
	 * @return Domain[]
	 */
	public function sign()
	{
		$domains = [];
		$this->acme->log('Запрашиваем токены для прохождения верификации');

		foreach ($this->domains as $domain_name => $domain) {
			/** @var Domain $domain */
			$domain->sign();
			$domain->trigger('signed', $domain);
			$this->trigger('signed:domain', $domain);

			$domains[$domain_name] = $domain;
		}

		$this->acme->log('Закончили процедуру получения токенов для верификации');
		$this->acme->log(PHP_EOL);
		$this->acme->log(PHP_EOL);

		$this->trigger('signed:complete', $domains);
		return $domains;
	}

	/**
	 * @throws Exception
	 */
	public function verify()
	{
		$domains = [];
		$this->acme->log('Начинаем процедуру верификации');

		foreach ($this->domains as $domain_name => $domain) {
			/** @var Domain $domain */
			$domain->verify();
			$domains[$domain_name] = $domain;
		}

		$this->acme->log('Закончили процедуру верификации');
		$this->acme->log(PHP_EOL);
		$this->acme->log(PHP_EOL);

		$this->trigger('verified:complete', $this);
	}

	/**
	 * @param null|PrivateKey $key
	 * @return Csr
	 */
	public function generateCsr($key = null)
	{
		return new Csr($key, array_keys($this->domains));
	}
}