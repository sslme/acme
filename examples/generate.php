<?php
include_once __DIR__ . "/../vendor/autoload.php";

use Sslme\Acme\AcmeClient;
use Sslme\Acme\Certificate;
use Sslme\Acme\CertificatesCollection;
use Sslme\Acme\Csr;
use Sslme\Acme\Domain;
use Sslme\Acme\DomainsCollection;
use Sslme\Acme\PrivateKey;

$domains = ['is-d.one'];
$privateKeyPath = __DIR__ . '/private_auth.pem';

function message($message)
{
	print sprintf('[%s] %s', date('d.m.Y / H:i:s'), $message) . PHP_EOL;
}

$client = new AcmeClient();

// Включаем режим отладки
$client->setVerbose( true );

if (!is_file($privateKeyPath))
{
	message('Генерируем ключ авторизации');

	$privateKey = new PrivateKey();
	$privateKey->savePrivateKeyTo($privateKeyPath);
	$privateKey->savePublicKeyTo(dirname($privateKeyPath) . DIRECTORY_SEPARATOR . 'public_auth.pem');
}

// Задаем ключ авторизации
$client->setAuthKey($privateKeyPath);

// Задаем домены
foreach ($domains as $domain_name) {
	$client->domains->add(new Domain($domain_name));
}

// Авторизация на серевере LetsEncrypt
$client->authenticate();
message('Выполнили авторизацию на сервере LetsEncrypt');

$client
	->certificates
	->on('generated:certificate', function (Certificate $certificate) {
		message('Сертификат ' . $certificate->getName() . ' успешно сгенерирован');
	})
	->on('generated:complete', function (CertificatesCollection $certificates) {
		message('Все сертификаты сгенерированы. Сохраняем');

		$certificates->get('fullchain')->saveTo(__DIR__ . '/certs/fullchain.pem');
		$certificates->get('chain')->saveTo(__DIR__ . '/certs/chain.pem');
		$certificates->get('cert')->saveTo(__DIR__ . '/certs/cert.pem');
	});

message('Начинаем процедуру верификации доменов');
$client->domains
	/*
	 * Токены для всех доменов получены
	*/
	->on('signed:domain', function(Domain $domain) use ($client) {
		message("\t" . 'Создаем http://'.$domain->toString().'/.well-known/acme-challenge/' . $domain->getToken());
		file_put_contents(__DIR__ . '/.well-known/acme-challenge/' . $domain->getToken(), $domain->getPayload());
	})
	/*
	 * Токены для всех доменов получены
	*/
	->on('signed:complete', function() use ($client) {
		message('Токены для всех доменов сгенерированы');

		// Запускаем проверку
		$client->domains->verify();
	})

	/*
	 * Все домены проверены
	*/
	->on('verified:complete', function($domains) use ($client) {
		message('Верификация пройдена успешно');

		/**
		 * @var DomainsCollection $domains
		 * @var string $csrPath
		 */
		$csrPath = __DIR__ . '/last.csr';

		// Проверяем наличие csr-ключа
		if (!is_file($csrPath))
		{
			message('Генерируем новый csr');
			// Новый
			$domainsKey = new PrivateKey();
			$domainsKey->savePrivateKeyTo(dirname($csrPath) . '/private.pem');
			$domainsKey->savePublicKeyTo(dirname($csrPath) . '/public.pem');

			$csr = $domains->generateCsr($domainsKey);
			$csr->saveTo($csrPath);

		} else {
			message('Используем сущестующий csr');
			// Существующий
			$csr = Csr::read($csrPath);
		}

		// Получаем сертификаты
		$client->generateCertificates($csr);
	})

	/*
	 * Верификация доменов
	 */
	->sign();