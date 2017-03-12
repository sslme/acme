<?php
namespace Sslme\Acme;

use Exception;

class Domain
{
	use EventsManager;

	const CHECK_STATUS_PENDING = 'pending';
	const CHECK_STATUS_INVALID = 'invalid';
	const CHECK_STATUS_VALID = 'valid';

	/** @var string $domain */
	private $domain;

	/** @var AcmeClient $acme */
	private $acme;

	/** @var null|string $token */
	public $token = null;

	/** @var null|string $verify_uri */
	public $verify_uri = null;

	/** @var null|string $check_status_uri */
	public $check_status_uri = null;

	/** @var null|string $payload */
	public $payload = null;

	/**
	 * Domain constructor.
	 * @param $domain
	 */
	public function __construct($domain)
	{
		$this->domain = $domain;
	}

	/**
	 * @param $acme
	 */
	public function setAcme(&$acme)
	{
		$this->acme = $acme;
	}

	/**
	 * @return string
	 */
	public function __toString()
	{
		return $this->toString();
	}

	/**
	 * @return string
	 */
	public function toString()
	{
		return $this->domain;
	}

	/**
	 * @return array
	 * @throws Exception
	 */
	public function sign()
	{
		$this->acme->log('Запрашиваем токен верификации для ' . $this->domain);
		$response = $this->acme->getClient()->signedRequest("/acme/new-authz", [
			"resource" => "new-authz",
			"identifier" => [
				"type" => "dns",
				"value" => $this->domain
			]
		], $this->acme->getAuthKey());

		$challenge = $this->extractChallenge($response);

		$this->setToken($challenge['token']);
		$this->setVerifyUri($challenge['uri']);
		$this->setCheckStatusUri($this->acme->getClient()->getLastResponse()['location']);

		$this->acme->log("\t" . 'Извлекли:');
		$this->acme->log("\t\t" . 'token: ' . $this->getToken());
		$this->acme->log("\t\t" . 'uri: ' . $this->getVerifyUri());
		$this->acme->log("\t\t" . 'location: ' . $this->getCheckStatusUri());

		$this->acme->log("\t" . 'Генерируем payload');
		$payload = $this
			->acme
			->getAuthKey()
			->getPayload($challenge['token']);

		$this->setPayload($payload);

		$this->acme->log("\t\t" . 'payload: ' . $this->getPayload());
		$this->acme->log(PHP_EOL);
	}

	/**
	 * @return bool
	 * @throws Exception
	 */
	public function verify()
	{
		$this->acme->log('Производим проверку ' . $this->domain);

		$result = $this
			->acme
			->getClient()
			->signedRequest(
				$this->getVerifyUri(), [
					"resource"          => "challenge",
					"type"              => "http-01",
					"keyAuthorization"  => $this->getPayload(),
					"token"             => $this->getToken()
				], 
				$this->acme->getAuthKey()
			);

		do {
			if (empty($result['status']) || $result['status'] == self::CHECK_STATUS_INVALID) {
				$this->acme->log("\t" . 'Верификация не удалась');
				throw new \Exception("Verification ended with error: " . json_encode($result));
			}

			if ($result['status'] === self::CHECK_STATUS_VALID) {
				$this->acme->log("\t" . 'Успешная верификация');
				$this->trigger('verified', $this);
				$process = false;
			} else if ($result['status'] === self::CHECK_STATUS_PENDING){
				$this->acme->log("\t" . 'Ожидаем');
				sleep(1);
				$process = true;

				$result = $this
					->acme
					->getClient()
					->request($this->getCheckStatusUri());
			} else {
				$this->acme->log("\t" . 'Получен неизвестный статус при проверки статуса верификации');
				throw new \Exception("Unknown status checked: " . json_encode($result));
			}
		} while ($process);

		return true;
	}

	/**
	 * @param string $token
	 */
	public function setToken($token)
	{
		$this->token = $token;
	}

	/**
	 * @param string $uri
	 */
	public function setVerifyUri($uri)
	{
		$this->verify_uri = $uri;
	}

	/**
	 * @param string $uri
	 */
	public function setCheckStatusUri($uri)
	{
		$this->check_status_uri = $uri;
	}

	/**
	 * @param $payload
	 */
	public function setPayload($payload)
	{
		$this->payload = $payload;
	}

	/**
	 * @return null|string
	 */
	public function getToken()
	{
		return $this->token;
	}

	/**
	 * @return null|string
	 */
	public function getVerifyUri()
	{
		return $this->verify_uri;
	}

	/**
	 * @return null|string
	 */
	public function getCheckStatusUri()
	{
		return $this->check_status_uri;
	}

	/**
	 * @return null|string
	 */
	public function getPayload()
	{
		return $this->payload;
	}

	/**
	 * @param $response
	 * @return mixed
	 * @throws Exception
	 */
	private function extractChallenge($response)
	{
		$challenge = array_reduce($response['challenges'], function ($v, $w) {
			return $v ? $v : ($w['type'] == 'http-01' ? $w : false);
		});

		if (!$challenge) {
			throw new \Exception("HTTP Challenge is not available. Whole response: " . json_encode($response));
		}

		return $challenge;
	}
}