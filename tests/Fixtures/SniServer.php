<?php

namespace WpOrg\Requests\Tests\Fixtures;

/**
 * Local TLS server used to verify Server Name Indication support.
 */
final class SniServer {

	/**
	 * Temporary directory containing the generated certificates.
	 *
	 * @var string
	 */
	private $directory;

	/**
	 * Certificate authority file path.
	 *
	 * @var string
	 */
	private $ca_file;

	/**
	 * Correct server certificate file path.
	 *
	 * @var string
	 */
	private $server_certificate;

	/**
	 * Correct server key file path.
	 *
	 * @var string
	 */
	private $server_key;

	/**
	 * Wrong server certificate file path.
	 *
	 * @var string
	 */
	private $wrong_certificate;

	/**
	 * Wrong server key file path.
	 *
	 * @var string
	 */
	private $wrong_key;

	/**
	 * Running Python server process.
	 *
	 * @var resource|null
	 */
	private $process;

	/**
	 * Process pipes.
	 *
	 * @var array
	 */
	private $pipes = [];

	/**
	 * Server URL.
	 *
	 * @var string
	 */
	private $url;

	/**
	 * Server output captured during startup.
	 *
	 * @var string
	 */
	private $server_output = '';

	/**
	 * Start the local TLS server.
	 *
	 * @throws \RuntimeException If the certificate or server setup fails.
	 */
	public function __construct() {
		$this->directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'requests-sni-' . uniqid('', true);

		if (!mkdir($this->directory, 0700, true)) {
			throw new \RuntimeException('Could not create the SNI test directory.');
		}

		try {
			$this->createCertificates();
			$this->startServer();
		} catch (\Exception $exception) {
			$this->close();
			throw $exception;
		}
	}

	/**
	 * Get the URL served by the local endpoint.
	 *
	 * @return string
	 */
	public function getUrl() {
		return $this->url;
	}

	/**
	 * Get the CA file used to sign the SNI certificate.
	 *
	 * @return string
	 */
	public function getCaFile() {
		return $this->ca_file;
	}

	/**
	 * Stop the server and remove generated files.
	 *
	 * @return void
	 */
	public function close() {
		if (is_resource($this->process)) {
			if (isset($this->pipes[0]) && is_resource($this->pipes[0])) {
				fclose($this->pipes[0]);
			}

			$status = proc_get_status($this->process);
			if ($status['running']) {
				proc_terminate($this->process);
				$deadline = microtime(true) + 1;
				do {
					usleep(10000);
					$status = proc_get_status($this->process);
				} while ($status['running'] && microtime(true) < $deadline);

				if ($status['running']) {
					proc_terminate($this->process, 9);
				}
			}

			proc_close($this->process);
			$this->process = null;
		}

		foreach ($this->pipes as $pipe) {
			if (is_resource($pipe)) {
				fclose($pipe);
			}
		}

		$this->pipes = [];

		if ($this->directory !== null && is_dir($this->directory)) {
			$files = glob($this->directory . DIRECTORY_SEPARATOR . '*');
			if (is_array($files)) {
				foreach ($files as $file) {
					if (is_file($file)) {
						unlink($file);
					}
				}
			}

			rmdir($this->directory);
			$this->directory = null;
		}
	}

	/**
	 * Ensure the child process is cleaned up if a test aborts unexpectedly.
	 */
	public function __destruct() {
		$this->close();
	}

	/**
	 * Generate a trusted and an untrusted server certificate.
	 *
	 * @return void
	 *
	 * @throws \RuntimeException If OpenSSL cannot create the certificates.
	 */
	private function createCertificates() {
		if (!function_exists('openssl_pkey_new') || !function_exists('openssl_csr_new')) {
			throw new \RuntimeException('The OpenSSL extension is required for the SNI test.');
		}

		$config_file = $this->directory . DIRECTORY_SEPARATOR . 'openssl.cnf';
		$config      = "[req]\n";
		$config     .= "prompt = no\n";
		$config     .= "distinguished_name = distinguished_name\n";
		$config     .= "req_extensions = server_ext\n\n";
		$config     .= "[distinguished_name]\n";
		$config     .= "CN = localhost\n\n";
		$config     .= "[server_ext]\n";
		$config     .= "basicConstraints = critical,CA:FALSE\n";
		$config     .= "keyUsage = critical,digitalSignature,keyEncipherment\n";
		$config     .= "subjectAltName = DNS:localhost\n\n";
		$config     .= "[ca_ext]\n";
		$config     .= "basicConstraints = critical,CA:TRUE,pathlen:1\n";
		$config     .= "keyUsage = critical,keyCertSign,cRLSign\n";
		$config     .= "subjectKeyIdentifier = hash\n";
		$config     .= "authorityKeyIdentifier = keyid:always,issuer\n";

		if (file_put_contents($config_file, $config) === false) {
			throw new \RuntimeException('Could not write the OpenSSL configuration.');
		}

		$ca_key = $this->createKey();
		$ca_csr = openssl_csr_new(['commonName' => 'Requests SNI test CA'], $ca_key, ['digest_alg' => 'sha256']);
		$ca     = openssl_csr_sign(
			$ca_csr,
			null,
			$ca_key,
			1,
			[
				'config'          => $config_file,
				'digest_alg'      => 'sha256',
				'x509_extensions' => 'ca_ext',
			]
		);

		if ($ca_csr === false || $ca === false) {
			throw new \RuntimeException('Could not create the SNI test certificate authority.');
		}

		$server_key = $this->createKey();
		$server_csr = openssl_csr_new(
			['commonName' => 'localhost'],
			$server_key,
			[
				'config'         => $config_file,
				'digest_alg'     => 'sha256',
				'req_extensions' => 'server_ext',
			]
		);
		$server     = openssl_csr_sign(
			$server_csr,
			$ca,
			$ca_key,
			1,
			[
				'config'          => $config_file,
				'digest_alg'      => 'sha256',
				'x509_extensions' => 'server_ext',
			]
		);

		$wrong_key = $this->createKey();
		$wrong_csr = openssl_csr_new(['commonName' => 'wrong.localhost'], $wrong_key, ['digest_alg' => 'sha256']);
		$wrong     = openssl_csr_sign($wrong_csr, null, $wrong_key, 1, ['digest_alg' => 'sha256']);

		if ($server_csr === false || $server === false || $wrong_csr === false || $wrong === false) {
			throw new \RuntimeException('Could not create the SNI test certificates.');
		}

		$this->ca_file            = $this->writeCertificate($ca, 'ca.pem');
		$this->server_certificate = $this->writeCertificate($server, 'server.pem');
		$this->server_key         = $this->writeKey($server_key, 'server-key.pem');
		$this->wrong_certificate  = $this->writeCertificate($wrong, 'wrong.pem');
		$this->wrong_key          = $this->writeKey($wrong_key, 'wrong-key.pem');
	}

	/**
	 * Create a private key.
	 *
	 * @return resource
	 *
	 * @throws \RuntimeException If OpenSSL cannot create the key.
	 */
	private function createKey() {
		$key = openssl_pkey_new(
			[
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'private_key_bits' => 2048,
			]
		);

		if ($key === false) {
			throw new \RuntimeException('Could not create an SNI test key.');
		}

		return $key;
	}

	/**
	 * Write a certificate to the temporary directory.
	 *
	 * @param resource $certificate Certificate resource.
	 * @param string   $name        File name.
	 *
	 * @return string
	 */
	private function writeCertificate($certificate, $name) {
		$pem = '';
		if (!openssl_x509_export($certificate, $pem)) {
			throw new \RuntimeException('Could not export an SNI test certificate.');
		}

		return $this->writeFile($name, $pem);
	}

	/**
	 * Write a private key to the temporary directory.
	 *
	 * @param resource $key  Private key resource.
	 * @param string   $name File name.
	 *
	 * @return string
	 */
	private function writeKey($key, $name) {
		$pem = '';
		if (!openssl_pkey_export($key, $pem)) {
			throw new \RuntimeException('Could not export an SNI test key.');
		}

		return $this->writeFile($name, $pem);
	}

	/**
	 * Write a temporary file.
	 *
	 * @param string $name    File name.
	 * @param string $contents File contents.
	 *
	 * @return string
	 */
	private function writeFile($name, $contents) {
		$path = $this->directory . DIRECTORY_SEPARATOR . $name;
		if (file_put_contents($path, $contents) === false) {
			throw new \RuntimeException('Could not write an SNI test file.');
		}

		return $path;
	}

	/**
	 * Start the Python TLS endpoint.
	 *
	 * The Python executable can be overridden with REQUESTS_SNI_PYTHON.
	 *
	 * @return void
	 *
	 * @throws \RuntimeException If the endpoint cannot be started.
	 */
	private function startServer() {
		$python = getenv('REQUESTS_SNI_PYTHON');
		if ($python === false || $python === '') {
			$python = 'python3';
		}

		$script   = __DIR__ . DIRECTORY_SEPARATOR . 'sni_server.py';
		$command  = escapeshellarg($python);
		$command .= ' ' . escapeshellarg($script);
		$command .= ' --correct-cert ' . escapeshellarg($this->server_certificate);
		$command .= ' --correct-key ' . escapeshellarg($this->server_key);
		$command .= ' --wrong-cert ' . escapeshellarg($this->wrong_certificate);
		$command .= ' --wrong-key ' . escapeshellarg($this->wrong_key);
		$command .= ' --expected-name localhost';

		$descriptors   = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];
		$this->process = proc_open($command, $descriptors, $this->pipes);

		if (!is_resource($this->process)) {
			throw new \RuntimeException('Could not start the SNI test server.');
		}

		stream_set_blocking($this->pipes[1], false);
		stream_set_blocking($this->pipes[2], false);

		$port     = null;
		$deadline = microtime(true) + 15;
		while (microtime(true) < $deadline) {
			$output = stream_get_contents($this->pipes[1]);
			if ($output !== false) {
				$this->server_output .= $output;
			}

			if (preg_match('/(?:^|\n)PORT=(\d+)(?:\n|$)/', $this->server_output, $matches)) {
				$port = (int) $matches[1];
				break;
			}

			$status = proc_get_status($this->process);
			if (!$status['running']) {
				break;
			}

			usleep(10000);
		}

		if ($port === null) {
			$error  = stream_get_contents($this->pipes[2]);
			$output = trim($this->server_output);
			$this->close();
			$message = 'The SNI test server did not start.';
			if ($output !== '') {
				$message .= ' Output: ' . $output;
			}

			if ($error !== false && trim($error) !== '') {
				$message .= ' Error: ' . trim($error);
			}

			throw new \RuntimeException($message);
		}

		$this->url = 'https://localhost:' . $port . '/';
	}
}
