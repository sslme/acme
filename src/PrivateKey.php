<?php
namespace Sslme\Acme;

use Sslme\Acme\Exceptions\PrivateKeyException;

class PrivateKey
{
	/** @var resource $key */
	private $key;

	/** @var string $path */
	private $path;

	/**
	 * Key constructor.
	 * @param null $key
	 */
	public function __construct($key = null)
	{
		if ($key === null) {
			$key = $this->generatePrivateKey();
		}

		$this->key = $key;
	}

	/**
	 * @param $file
	 * @return PrivateKey
	 * @throws PrivateKeyException
	 */
	static public function read($file)
	{
		if (($key = openssl_pkey_get_private('file://' . $file)) === FALSE) {
			throw new PrivateKeyException(openssl_error_string());
		}
		$privateKey = new self($key);
		$privateKey->setPath($file);

		return $privateKey;
	}

	/**
	 * @param $path
	 * @return string
	 */
	public function setPath($path)
	{
		return $this->path = $path;
	}

	/**
	 * @return string
	 */
	public function getPath()
	{
		return $this->path;
	}

	/**
	 * @return mixed
	 * @throws PrivateKeyException
	 */
	public function getPrivateKey()
	{
		if (!openssl_pkey_export($this->getResource(), $privateKey)) {
			throw new PrivateKeyException("Export key failed");
		}

		return $privateKey;
	}

	/**
	 * @return null|resource
	 */
	public function getResource()
	{
		return $this->key;
	}

	/**
	 * @param $path
	 * @return int
	 * @throws PrivateKeyException
	 */
	public function savePrivateKeyTo($path)
	{
		$this->path = $path;

		return file_put_contents($path, $this->getPrivateKey());
	}

	/**
	 * @param $path
	 * @return int
	 */
	public function savePublicKeyTo($path)
	{
		return file_put_contents($path, $this->getPublicKey());
	}

	/**
	 * @return string
	 */
	public function getPublicKey()
	{
		return $this->getDetails()['key'];
	}

	/**
	 * @return array
	 */
	public function getDetails()
	{
		return openssl_pkey_get_details($this->key);
	}

	/**
	 * @param $token
	 * @return string
	 */
	public function getPayload($token)
	{
		$details = $this->getDetails();

		$header = [
			"e" => Helpers::safeEncode($details["rsa"]["e"]),
			"kty" => "RSA",
			"n" =>  Helpers::safeEncode($details["rsa"]["n"])
		];

		return sprintf('%s.%s', $token,  Helpers::safeEncode(hash('sha256', json_encode($header), true)));
	}

	/**
	 * @return resource
	 */
	private function generatePrivateKey()
	{
		return openssl_pkey_new([
			"private_key_type" => OPENSSL_KEYTYPE_RSA,
			"private_key_bits" => 4096
		]);
	}

	public static function parsePem($body)
	{
		$pem = chunk_split(base64_encode($body), 64, "\n");
		return sprintf("-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n", $pem);
	}
}