<?php
namespace Sslme\Acme;

use Sslme\Acme\Exceptions\PrivateKeyException;

class AcmeClient
{
	use EventsManager;

	const LICENSE_URL = 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf';
	const HOST = 'https://acme-v01.api.letsencrypt.org';

	/** @var DomainsCollection $domains */
	public $domains;

	/** @var CertificatesCollection $certificates */
	public $certificates;

	/** @var bool #verbose */
	private $verbose = false;

	/** @var PrivateKey $authKey */
	private $authKey;

	/** @var Client $client */
	private $client;

	/**
	 * Acme constructor.
	 */
	public function __construct()
	{
		$this->client = new Client();
		$this->client->setHost(self::HOST);
		
		$this->domains = new DomainsCollection();
		$this->domains->setAcme($this);

		$this->certificates = new CertificatesCollection();
	}

	/**
	 * @param bool $verbose
	 * @return $this
	 */
	public function setVerbose($verbose = false)
	{
		$this->verbose = $verbose;
		return $this;
	}

	/**
	 * @param $domain
	 * @return $this
	 */
	public function addDomain($domain)
	{
		if (is_array($domain))
		{
			$this->domains = array_merge($domain);
		}

		$this->domains[] = $domain;
		return $this;
	}

	/**
	 * @param $file
	 * @return PrivateKey
	 * @throws PrivateKeyException
	 */
	public function setAuthKey($file)
	{
		return $this->authKey = PrivateKey::read($file);
	}

	/**
	 * @return PrivateKey
	 */
	public function getAuthKey()
	{
		return $this->authKey;
	}

	/**
	 * @return bool
	 */
	public function authenticate()
	{
		$this->log('Производим авторизацию на сервере LetsEncrypt');

		return $this->client->signedRequest('/acme/new-reg', [
			'resource' => 'new-reg',
			'agreement' => self::LICENSE_URL
		], $this->getAuthKey());
	}

	/**
	 * @param $message
	 */
	function log($message)
	{
		if (empty(trim($message)) && $this->verbose === true)
		{
			print PHP_EOL;
			return;
		}

		if ($this->verbose === true)
			print sprintf('[%s] %s', date('d.m.Y / H:i:s'), $message) . PHP_EOL;
	}

	/**
	 * @param $csr
	 * @return array
	 * @throws \Exception
	 */
	public function generateCertificates(Csr $csr)
	{
		$this->log('Начинаем процедуру генерации сертификатов');

		$result = $this
			->client
			->signedRequest("/acme/new-cert", [
					'resource'  => 'new-cert',
					'csr'       => $csr->getContent()
				],
				$this->getAuthKey()
			);

		$code = $this->client->getLastResponse()['code'];

		if ($code !== 201)
			throw new \Exception("Invalid response code: " . $code . ", " . json_encode($result));

		$location = $this->client->getLastResponse()['location'];

		$certificates = [];

		while (true) {
			$result = $this
				->client
				->request($location);

			$code = $this->client->getLastResponse()['code'];

			$this->log('Получен статус ' . $code);

			if ($code == 202) {
				$this->log('Ожидаем');
				sleep(1);
			} else if ($code == 200) {
				$this->log('Извлекаем сертификаты');
				$certificates[] = PrivateKey::parsePem($result);

				$links = $this
					->client
					->getLastLinks();

				foreach ($links as $link) {
					$result = $this
						->client
						->request($link);

					$certificates[] = PrivateKey::parsePem($result);
				}
				break;
			} else {
				$this->log('Неизвестный статус');
				throw new \Exception("http code: " . $code);
			}
		}

		$this
			->certificates
				->add(new Certificate('fullchain', implode("\n", $certificates)))
				->add(new Certificate('cert', array_shift($certificates)))
				->add(new Certificate('chain', implode("\n", $certificates)));

		$this->certificates->trigger('generated:complete', $this->certificates);

		return $certificates;
	}

	/**
	 * @return Client
	 */
	public function getClient()
	{
		return $this->client;
	}
}