<?php
namespace Sslme\Acme;

use Sslme\Acme\Exceptions\CsrException;

class Csr
{
	/** @var PrivateKey $key */
	private $key;

	/** @var array $domains */
	private $domains = [];

	/** @var resource $csr */
	private $csr;

	/** @var bool $hasNew */
	private $hasNew = false;

	private $content = null;

	/**
	 * Csr constructor.
	 * @param PrivateKey|string $key
	 * @param array $domains
	 * @param string $state
	 * @param string $countryCode
	 * @throws \Exception
	 */
	public function __construct($key, array $domains = [], $state = 'Czech Republic', $countryCode = 'CZ')
	{
		if ($key instanceof PrivateKey && !empty($domains)) {
			$this->domains = $domains;
			$this->key = $key;
			$this->hasNew = true;

			$tmp = tmpfile();

			$path = $this->createConfigFile($tmp);

			$resourceKey = $this->key->getResource();

			$csr = openssl_csr_new(
				[
					"CN" => reset($this->domains),
					"ST" => $state,
					"C" => $countryCode,
					"O" => "Unknown",
				],
				$resourceKey
				,
				[
					"config" => $path,
					"digest_alg" => "sha256"
				]
			);

			fclose($tmp);

			if (!$csr) throw new \Exception(openssl_error_string());

			$this->csr = $csr;
		} else {
			$this->content = $key;
		}
	}

	/**
	 * @param $path
	 * @return Csr
	 */
	public static function read($path)
	{
		$certificate = file_get_contents($path);
		$content = self::parseContentFromCertificate($certificate);

		return new self($content);
	}

	/**
	 * @return string
	 */
	public function getCertificate()
	{
		if ($this->hasNew) {
			openssl_csr_export($this->csr, $csr);
		} else {
			$csr = self::generateCertificateFromContent($this->content);
		}

		return $csr;
	}

	/**
	 * @param $path
	 * @return int
	 * @throws CsrException
	 */
	public function saveTo($path)
	{
		if (!$this->hasNew)
			throw new CsrException('Existing CSR does not save');

		return file_put_contents($path, $this->getCertificate());
	}

	/**
	 * @return null|PrivateKey|string
	 */
	public function getContent()
	{
		if ($this->hasNew) {
			return self::parseContentFromCertificate($this->getCertificate());
		} else {
			return $this->content;
		}
	}

	/**
	 * @param $certificateContent
	 * @return string
	 */
	public static function parseContentFromCertificate($certificateContent)
	{
		preg_match('~REQUEST-----(.*)-----END~s', $certificateContent, $matches);
		return trim(Helpers::safeEncode(base64_decode($matches[1])));
	}

	/**
	 * @param $content
	 * @return null|string
	 */
	public static function generateCertificateFromContent($content = null)
	{
		// Todo: Реализовать safeDecode и сделать врап для меток
		return $content;
	}

	/**
	 * @param array $domains
	 * @return string
	 */
	private function generateConfig(array $domains = [])
	{
		if (empty($domains)) {
			$domains = $this->domains;
		}

		$dns = array_map(function ($domain) {
			return "DNS:" . $domain;
		}, $domains);

		$subjectAltName = implode(",", $dns);

		return  'HOME = .' . PHP_EOL .
				'RANDFILE = $ENV::HOME/.rnd' . PHP_EOL .
				'[ req ]' . PHP_EOL .
				'default_bits = 2048' . PHP_EOL .
				'default_keyfile = private.pem' . PHP_EOL .
				'distinguished_name = req_distinguished_name' . PHP_EOL .
				'req_extensions = v3_req' . PHP_EOL .
				'[ req_distinguished_name ]' . PHP_EOL .
				'countryName = Country Name (2 letter code)' . PHP_EOL .
				'[ v3_req ]' . PHP_EOL .
				'basicConstraints = CA:FALSE' . PHP_EOL .
				'subjectAltName = ' . $subjectAltName . PHP_EOL .
				'keyUsage = nonRepudiation, digitalSignature, keyEncipherment';
	}

	/**
	 * @return mixed
	 */
	private function createConfigFile($file)
	{
		$meta = stream_get_meta_data($file);
		$path = $meta["uri"];

		fwrite($file, $this->generateConfig($this->domains));

		return $path;
	}
}