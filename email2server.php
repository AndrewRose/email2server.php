#!/usr/bin/php
<?php
/*
 This file is part of email2server.php
 http://github.com/AndrewRose/email2server.php
 License: GPL; see below
 Copyright Andrew Rose (hello@andrewrose.co.uk) 2012

    cached.php is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    cached.php is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with cached.php.  If not, see <http://www.gnu.org/licenses/>
*/

define('DOCROOT', '/var/lib/email2server/');
define('AUTO_ORGANISE_FILES', TRUE);

class Handler
{
	public $domainName = FALSE;
	public $connections = [];
	public $buffers = [];
	public $maxRead = 255;
	public $settings = [];
	private $backend = FALSE;

	public function __construct($settings)
	{
		$this->settings = $settings; 
		$this->domainName = $settings['domain'];

		// currently broken: https://bugs.php.net/bug.php?id=61258&thanks=3
		/* ssl setup **/
		/*$dn = [
			"countryName" => "UK",
			"stateOrProvinceName" => "Somerset",
			"localityName" => "Glastonbury",
			"organizationName" => "The Brain Room Limited",
			"organizationalUnitName" => "PHP Documentation Team",
			"commonName" => "Wez Furlong",
			"emailAddress" => "wez@example.com"
		];

		$privkey = openssl_pkey_new();
		$cert    = openssl_csr_new($dn, $privkey);
		$cert    = openssl_csr_sign($cert, null, $privkey, 365);

		$pem_passphrase = 'comet';
		$pem = [];
		openssl_x509_export($cert, $pem[0]);
		openssl_pkey_export($privkey, $pem[1], $pem_passphrase);
		$pem = implode($pem);

		$pemfile = './server.pem';
		file_put_contents($pemfile, $pem);

		$context = stream_context_create();
		stream_context_set_option($context, 'ssl', 'local_cert', $pemfile);
		stream_context_set_option($context, 'ssl', 'passphrase', $pem_passphrase);
		stream_context_set_option($context, 'ssl', 'allow_self_signed', true);
		stream_context_set_option($context, 'ssl', 'verify_peer', false);


		$socket = stream_socket_server ('ssl://0.0.0.0:993', $errno, $errstr, STREAM_SERVER_BIND|STREAM_SERVER_LISTEN, $context); //143
		//stream_socket_enable_crypto($socket, TRUE, STREAM_CRYPTO_METHOD_SSLv23_SERVER);
		*/
		/** **/

		$socket = stream_socket_server ('tcp://0.0.0.0:25', $errno, $errstr);
		stream_set_blocking($socket, 0);
		$base = event_base_new();
		$event = event_new();
		event_set($event, $socket, EV_READ | EV_PERSIST, [&$this, 'ev_accept'], $base);
		event_base_set($event, $base);
		event_add($event);
		event_base_loop($base);
	}

	protected function ev_accept($socket, $flag, $base)
	{
		static $id = 0;
		$connection = stream_socket_accept($socket);
		stream_set_blocking($connection, 0);
		$id += 1;

		$this->connections[$id]['cnx'] = $connection;
		$this->connections[$id]['clientData'] = '';
		$this->connections[$id]['dataMode'] = FALSE;
		$this->connections[$id]['message'] = [
			'MAIL FROM' => FALSE,
			'RCPT TO' => FALSE,
			'DATA' => FALSE
		];

		$buffer = event_buffer_new($connection, [&$this, 'ev_read'], NULL, [&$this, 'ev_error'], $id);

		event_buffer_base_set($buffer, $base);
		//event_buffer_timeout_set($buffer, 30, 30);
		event_buffer_watermark_set($buffer, EV_READ, 0, $this->maxRead);
		//event_buffer_priority_set($buffer, 10);
		event_buffer_enable($buffer, EV_READ | EV_WRITE);
		$this->buffers[$id] = $buffer;

		$this->ev_write($id, '220 '.$this->domainName." wazzzap?\r\n");
	}

	protected function ev_error($buffer, $error, $id)
	{
//echo "error: ".$error."\n";
//echo event_buffer_read($buffer, 255);
		$this->ev_close($id);
	}

	protected function ev_close($id)
	{
		event_buffer_disable($this->buffers[$id], EV_READ | EV_WRITE);
		event_buffer_free($this->buffers[$id]);
		fclose($this->connections[$id]['cnx']);
		unset($this->buffers[$id], $this->connections[$id]);
	}

	protected function ev_write($id, $string)
	{
//echo 'S: '.$string;
		event_buffer_write($this->buffers[$id], $string);
	}

	protected function ev_read($buffer, $id)
	{
		$this->connections[$id]['clientData'] .= event_buffer_read($buffer, $this->maxRead);
		$clientDataLen = strlen($this->connections[$id]['clientData']);

//echo 'C: '.$this->connections[$id]['clientData'];
		if(	!$this->connections[$id]['dataMode'] && 
			$this->connections[$id]['clientData'][$clientDataLen-1] == "\n" &&
			$this->connections[$id]['clientData'][$clientDataLen-2] == "\r")
		{
			// remove the trailing \r\n
			$line = substr($this->connections[$id]['clientData'], 0, strlen($this->connections[$id]['clientData'])-2);
			$this->connections[$id]['clientData'] = '';
			$this->cmd($buffer, $id, $line);
		}
		else if($this->connections[$id]['dataMode'] &&
			$this->connections[$id]['clientData'][$clientDataLen-1] == "\n" &&
			$this->connections[$id]['clientData'][$clientDataLen-2] == "\r" &&
			$this->connections[$id]['clientData'][$clientDataLen-3] == "." &&
			$this->connections[$id]['clientData'][$clientDataLen-4] == "\n" &&
			$this->connections[$id]['clientData'][$clientDataLen-5] == "\r")
		{

//TODO remove the trailing dot from .. lines.
			// remove trailing \r\n.\r\n
			$this->process($this->connections[$id]['message']['MAIL FROM'], $this->connections[$id]['message']['RCPT TO'], substr($this->connections[$id]['clientData'], 0, strlen($this->connections[$id]['clientData'])-5));

			$this->connections[$id]['clientData'] = '';
			$this->connections[$id]['dataMode'] = FALSE;
			$this->connections[$id]['message'] = [
				'MAIL FROM' => FALSE,
				'RCPT TO' => FALSE,
				'DATA' => FALSE
			];

			$this->ev_write($id, "250 2.0.0 OK.\r\n");
		}
	}

	protected function cmd($buffer, $id, $line)
	{
		echo "got cmd: ".$line."\n";
		//$line = strtoupper($line);
		switch($line)
		{
			case strncmp('EHLO ', $line, 4):
			{
				$this->ev_write($id, "250 OK ehlo\r\n");
			}
			break;

			case strncmp('HELO ', $line, 4):
			{
				$this->ev_write($id, "250 OK helo\r\n");
			}
			break;

			case strncmp('MAIL FROM: ', $line, 10):
			{
				$this->connections[$id]['message']['MAIL FROM'] = substr($line, 10, strlen($line)-2);
				$this->ev_write($id, "250 2.1.0 OK\r\n");
			}
			break;

			case strncmp('RCPT TO: ', $line, 8):
			{
				if(!$this->connections[$id]['message']['MAIL FROM'])
				{
					$this->ev_write($id, "503 5.5.1 MAIL first.\r\n");
				}
				else
				{
					$this->connections[$id]['message']['RCPT TO'] = substr($line, 8, strlen($line)-2);
					$this->ev_write($id, "250 2.1.5 OK\r\n");
				}
			}
			break;

			case strncmp('DATA ', $line, 4):
			{
				if(!$this->connections[$id]['message']['MAIL FROM'])
				{
					$this->ev_write($id, "503 5.5.1 MAIL first.\r\n");
				}
				else if(!$this->connections[$id]['message']['RCPT TO'])
				{
					$this->ev_write($id, "503 5.5.1 RCPT first.\r\n");
				}
				else
				{
					$this->connections[$id]['clientData'] = '';
					$this->connections[$id]['dataMode'] = TRUE;
					$this->ev_write($id, "354 Go ahead\r\n");
				}
			}
			break;

			case strncmp('QUIT', $line, 3):
			{
				$this->ev_write($id, "250 OK quit\r\n");
				$this->ev_close($id);
			}
			break;
			default:
			{
				echo 'unknown command: '.$line."\n";
			}
			break;
		}
	}
/*
Array
(
    [headers] => Array
        (
            [content-type] => image/png; name="img.png"
            [content-disposition] => attachment; filename="img.png"
            [content-transfer-encoding] => base64
        )

    [starting-pos] => 1617
    [starting-pos-body] => 1773
    [ending-pos] => 10348
    [ending-pos-body] => 10348
    [line-count] => 116
    [body-line-count] => 111
    [charset] => us-ascii
    [transfer-encoding] => base64
    [content-name] => img.png
    [content-type] => image/png
    [disposition-filename] => img.png
    [content-disposition] => attachment
    [content-base] => /
)
*/
	public function process($from, $to, $data)
	{
		if(AUTO_ORGANISE_FILES)
		{
			$from = str_replace('<', '', str_replace('>', '', $from));
			$to = str_replace('<', '', str_replace('>', '', $to));
			if(!filter_var($from, FILTER_VALIDATE_EMAIL) || !filter_var($to, FILTER_VALIDATE_EMAIL))
			{
				return FALSE;
			}

			$baseDir = DOCROOT.'/'.$to.'/'.$from;
		}
		else
		{
			$baseDir = DOCROOT;
		}

		if(!is_dir($baseDir))
		{
			if(!mkdir($baseDir, 0777, TRUE))
			{
				echo "Failed to create directory: ".$baseDir."\n";
				return FALSE;
			}
		}

		$mime = mailparse_msg_create();
		mailparse_msg_parse($mime,$data);
		$struct = mailparse_msg_get_structure($mime);

		foreach($struct as $section)
		{
			$part = mailparse_msg_get_part($mime, $section); 
			$part = mailparse_msg_get_part_data($part); 

			if(!in_array($part['content-type'], ['image/png']))
			{
				continue;
			}

			$filename = $baseDir.'/';
			//if(isset($part['content-disposition']) && !empty($part['content-disposition']))
			//{
			//	$filename .= preg_replace('/[^0-9a-z\.\_\-]/i','',$part['content-disposition']);
			//}
			//else
			//{
				$filename .= preg_replace('/[^0-9a-z\.\_\-]/i','',$part['content-name']);
			//}

			if(isset($part['headers']['content-type']))
			{
				//if(explode(';',$part['headers']['content-type'])[0] == 'image/png')
				//{
					$filedata = substr($data, $part['starting-pos-body'], $part['ending-pos-body']);
					$filedata = base64_decode($filedata);
					file_put_contents($filename, $filedata);

					//$finfo = finfo_open(FILEINFO_MIME_TYPE);
					//$mimeType = finfo_file($finfo, DOCROOT.$filename) . "\n";
					//finfo_close($finfo);
				//}
			}
		} 

	}
}

$pid = pcntl_fork();
if($pid)
{
	exit();
}
new Handler($pid);
