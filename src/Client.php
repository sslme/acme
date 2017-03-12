<?php
namespace Sslme\Acme;

use Exception;

class Client
{
	/** @var array $lastResponse */
	private $lastResponse;

	/** @var string $host */
	private $host;

	/**
	 * @param $method
	 * @param $url
	 * @param null $data
	 * @return mixed|string
	 * @throws Exception
	 */
	private function curl($method, $url, $data = null)
	{
		$headers = ['Accept: application/json', 'Content-Type: application/json'];
		$handle = curl_init();
		curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->host . $url);
		curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($handle, CURLOPT_HEADER, true);

		switch ($method) {
			case 'GET':
				break;
			case 'POST':
				curl_setopt($handle, CURLOPT_POST, true);
				curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
				break;
		}
		$response = curl_exec($handle);

		if(curl_errno($handle)) {
			throw new \Exception('Curl: '.curl_error($handle));
		}

		$header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

		$header = substr($response, 0, $header_size);
		$body = substr($response, $header_size);

		$this->lastResponse['header'] = $header;
		$this->lastResponse['code'] = curl_getinfo($handle, CURLINFO_HTTP_CODE);

		if(preg_match('~Location: (.+)~i', $header, $matches)) {
			$this->lastResponse['location'] = trim($matches[1]);
		} else {
			$this->lastResponse['location'] = null;
		}

		$data = json_decode($body, true);

		return $data === null ? $body : $data;
	}

	/**
	 * @return array
	 */
	public function getLastResponse()
	{
		return $this->lastResponse;
	}

	/**
	 * @param $url
	 * @return mixed|string
	 */
	public function request($url)
	{
		return $this->curl('GET', $url);
	}

	/**
	 * @param $url
	 * @param $data
	 * @return mixed|string
	 * @throws Exception
	 */
	public function post($url, $data)
	{
		return $this->curl('POST', $url, $data);
	}

	/**
	 * @param $uri
	 * @param $data
	 * @param PrivateKey $key
	 * @return bool
	 */
	public function signedRequest($uri, $data, PrivateKey $key)
	{
		$details = $key->getDetails();

		$header = [
			"alg" => "RS256",
			"jwk" => [
				"kty" => "RSA",
				"n" => Helpers::safeEncode($details["rsa"]["n"]),
				"e" => Helpers::safeEncode($details["rsa"]["e"]),
			]
		];

		$protectedHeader = $header;
		$protectedHeader['nonce'] = $this->getLastNonce();

		$payload = Helpers::safeEncode(str_replace('\\/', '/', json_encode($data)));
		$protected = Helpers::safeEncode(str_replace('\\/', '/', json_encode($protectedHeader)));

		openssl_sign($protected . '.' . $payload, $signed, $key->getResource(), "SHA256");

		$signature = Helpers::safeEncode($signed);

		$request = [
			'header'    => $header,
			'protected' => $protected,
			'payload'   => $payload,
			'signature' => $signature
		];

		return $this->post($uri, json_encode($request));
	}

	/**
	 * @return string
	 */
	public function getLastNonce()
	{
		if(preg_match('~Replay\-Nonce: (.+)~i', $this->lastResponse['header'], $matches)) {
			return trim($matches[1]);
		}

		$this->curl('GET', '/directory');
		return $this->getLastNonce();
	}

	/**
	 * @return mixed
	 */
	public function getLastLinks()
	{
		preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastResponse['header'], $matches);
		return $matches[1];
	}

	/**
	 * @param string $host
	 */
	public function setHost($host)
	{
		$this->host = $host;
	}
}