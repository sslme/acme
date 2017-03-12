<?php
namespace Sslme\Acme;

class Helpers
{
	static function safeEncode($data)
	{
		return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
	}
}