<?php

require_once 'config.php';

global $fv, $pv; // globals for pushing data to the template

function main()
{
	global $fv, $pv;

	configCheck();

	$action = $_POST['ACTION'] ?? null;
	$apiKey = $_POST['API_KEY'] ?? null;
	$clientId = $_POST['CLIENT_ID'] ?? null;
	$clientSecret = $_POST['CLIENT_SECRET'] ?? null;
	$refreshToken = $_POST['REFRESH_TOKEN'] ?? null;

	$code = $_GET['code'] ?? null;
	$state = $_GET['state'] ?? null;

	$fv['ACTION'] = htmlspecialchars($action);
	$fv['API_KEY'] = htmlspecialchars($apiKey);
	$fv['CLIENT_ID'] = htmlspecialchars($clientId);
	$fv['CLIENT_SECRET'] = htmlspecialchars($clientSecret);
	$fv['REFRESH_TOKEN'] = htmlspecialchars($refreshToken);

	if ($action === 'reset') {
		handleReset();
	}

	$seed = getSetEncryptionSeed();
	$pv['ENCRYPTION_SEED'] = $seed;

	if ($action === 'refresh') {
		return handleRefresh($apiKey, $clientId, $clientSecret, $refreshToken);
	}

	if ($action === 'authorize') {
		return handleAuthorize($apiKey, $clientId, $clientSecret);
	}

	if (!empty($state)) {
		return handleCallback($state, $code);
	}
}

/**
 * Simple validation that the config file has expected settings
 *	with non-empty values.
 *
 * @return null
 */
function configCheck()
{
	$required = [
		'SCRIPT_URI',
		'PS_URL_BASE',
		'TEST_MEDIA_ID',
		'CIPHER',
	];

	foreach ($required as $constant) {
		$value = constant($constant);
		if (empty($value)) {
			throw new Exception('config.php missing: ' . $constant);
		}
	}
}

/**
 * Retrieves a random "seed" to be used to generate a key to encrypt state
 * data in transit. The seed is stored in a temporary session cookie so that
 * it will persist across the different stages of OAuth redirects.
 *
 * @return string
 */
function getSetEncryptionSeed()
{
	$seed = $_COOKIE['encryption_seed'] ?? null;

	if (!empty($seed)) {
		return $seed;
	}

	$seed = bin2hex(random_bytes(32));

	$scheme = parse_url(SCRIPT_URI, PHP_URL_SCHEME);
	$path = parse_url(SCRIPT_URI, PHP_URL_PATH);
	$host = parse_url(SCRIPT_URI, PHP_URL_HOST);

	$name = 'encryption_seed';
	$expires = 0;
	$secure = ($scheme === 'https') ? true : false;
	$httponly = true;

	// set for future requests
	setcookie(
		$name,
		$seed,
		$expires,
		$path,
		$host,
		$secure,
		$httponly
	);

	// set for current request
	$_COOKIE['encryption_seed'] = $seed;

	return $seed;
}

/**
 * Encrypt the state data.
 *
 * @param string $plaintext the data to encrypt
 *
 * @return string Encrypted state data, Base64 encoded.
 */
function encryptState($plaintext)
{
	$seed = $_COOKIE['encryption_seed'];

	// this would not be good for serious encryption,
	// but is sufficient just to generate a sufficiently long key
	// in a reliable way
	$key = hash_hmac('sha512', $seed, $seed);

	$ivlen = openssl_cipher_iv_length(CIPHER);
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext_raw = openssl_encrypt($plaintext, CIPHER, $key, OPENSSL_RAW_DATA, $iv);
	$iv_and_ciphertext_raw = $iv . $ciphertext_raw;
	$ciphertext = base64_encode($iv_and_ciphertext_raw);

	return $ciphertext;
}

/**
 * Decrypt the state data.
 *
 * @param string $ciphertext the data to decrypt
 *
 * @return string Plaintext state data.
 */
function decryptState($ciphertext)
{
	$seed = $_COOKIE['encryption_seed'];
	$key = hash_hmac('sha512', $seed, $seed);

	$iv_and_ciphertext_raw = base64_decode($ciphertext);
	$ivlen = openssl_cipher_iv_length(CIPHER);
	$iv = substr($iv_and_ciphertext_raw, 0, $ivlen);
	$ciphertext_raw = substr($iv_and_ciphertext_raw, $ivlen);
	$plaintext = openssl_decrypt($ciphertext_raw, CIPHER, $key, OPENSSL_RAW_DATA, $iv);

	return $plaintext;
}

function v4Get($apiKey, $endpoint, $token = null)
{
	$data = $data ?? [];
	$baseUrl = PS_URL_BASE . 'psapi/v4.0/';
	$url = $baseUrl . $endpoint;
	$headers = [
		'Accept: application/json',
		'X-PS-Api-Key: ' . $apiKey,
	];

	return apiCall('GET', $url, $data, $headers, $token);
}

function v4Post($apiKey, $endpoint, $data = null, $token = null)
{
	$data = $data ?? [];
	$baseUrl = PS_URL_BASE . 'psapi/v4.0/';
	$url = $baseUrl . $endpoint;
	$headers = [
		'Accept: application/json',
		'X-PS-Api-Key: ' . $apiKey,
	];

	return apiCall('POST', $url, $data, $headers, $token);
}

/**
 * Makes generic API calls with Curl.
 *
 * @param string $method GET || POST
 * @param string $url Full URL to call
 * @param array $data Associate array of form data for POST requests
 * @param array $headers List of request headers
 * @param string $token Bearer token
 *
 * @return array Decoded response data
 */
function apiCall($method, $url, $data, $headers, $token = null)
{
	if (!empty($token)) {
		$headers[] = 'Authorization: Bearer ' . $token;
	}

	$ch = curl_init();

	switch ($method) {
	case 'POST':
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
		break;
	case 'GET':
	default:
		// curl defaults to GET
		break;
	}

	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

	$response = curl_exec($ch);
	$responseCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
	$curlError = curl_error($ch);

	if ($responseCode !== 200 || $curlError) {
		// there are many things we might potentially want to see
		// when debugging curl API errors
		$errMsg = sprintf(
			'CODE: %s; ERROR: %s; RETURN: %s; URL: %s',
			strval($responseCode),
			strval($curlError),
			strval($response),
			$url
		);
		throw new Exception($errMsg);
	}

	$response = $response ?? '{}';
	$response = json_decode($response, true);

	return $response;
}

/**
 * Unsets the encryption seed upon form reset.
 *
 * @return null
 */
function handleReset()
{
	// for future requests
	setcookie('encryption_seed');

	// for current request
	unset($_COOKIE['encryption_seed']);
}

/**
 * Initiates the authorization step of OAuth:
 *	- Validates user input
 *	- performs the redirect to the delegation form
 *
 * @param string $apiKey V4 API Key
 * @param string $clientId OAuth Client ID
 * @param string $clientSecret OAuth Client Secret
 *
 * @return null
 */
function handleAuthorize($apiKey, $clientId, $clientSecret)
{
	global $fv, $pv;

	// validate input
	$requiredFields = [
		'API_KEY' => $apiKey,
		'CLIENT_ID' => $clientId,
		'CLIENT_SECRET' => $clientSecret,
	];
	foreach ($requiredFields as $field => $value) {
		if (empty($value)) {
			throw new Exception('Missing field: ' . $field);
		}
	}

	// check API key by sending a test request
	// we don't actually care about what it returns,
	// just that ApiKeyInvalidException wasn't thrown.
	v4Get($apiKey, 'media/' . TEST_MEDIA_ID);

	// we'll need this information later;
	// to preserve it, we can send it as encrypted "state" data
	// through the OAuth flow.
	$state = implode('|', [
		'photoshelter',
		$apiKey,
		$clientId,
		$clientSecret
	]);
	$state = encryptState($state);

	$params = [
		'response_type' => 'code',
		'client_id' => $clientId,
		'state' => $state,
		'redirect_uri' => SCRIPT_URI,
		'api_key' => $apiKey,
	];
	$queryString = http_build_query($params);

	header('Location: ' . PS_URL_BASE . 'psapi/v4.0/oauth/authorize?' . $queryString);
}

/**
 * Handles the callback redirect from PhotoShelter:
 *	- validates the state data
 *	- exchanges the authorization code for a bearer (access) token
 *	- uses bearer token to make an arbitrary request (user/session)
 *
 * @param string $state State data sent in the redirect
 * @param string $code Authorization code sent in the redirect
 *
 * @return null
 */
function handleCallback($state, $code)
{
	global $fv, $pv;

	$pv['STEP'] = 'CALLBACK';

	$fv['state_raw'] = htmlspecialchars($state);
	$fv['code'] = htmlspecialchars($code);

	$state = decryptState($state);
	$fv['state'] = htmlspecialchars($state);

	$stateA = explode('|', $state);
	if (count($stateA) !== 4) {
		throw new Exception('Invalid state: ' . $state);
	}

	list($app, $apiKey, $clientId, $clientSecret) = $stateA;

	// exchange code for token
	$data = [
		'code' => $code,
		'grant_type' => 'authorization_code',
		'redirect_uri' => SCRIPT_URI,
		'client_id' => $clientId,
		'client_secret' => $clientSecret,
	];

	// used for the token refresh request
	$pv['state_decoded'] = $data;
	$pv['api_key'] = $apiKey;

	$response = v4Post($apiKey, 'oauth/token', $data);
	$accessToken = $fv['access_token'] = $response['access_token'];
	$refreshToken = $fv['refresh_token'] = $response['refresh_token'];

	// get user session: proof the bearer token works
	$response = v4Get($apiKey, 'user/session', $accessToken);
	if (!isset($response['data']['attributes']['user_id'])) {
		throw new Exception('Error getting user session: ' . json_encode($response));
	}
	$session = $response['data']['attributes'];

	$pv['SESSION'] = $session;
}

function handleRefresh($apiKey, $clientId, $clientSecret, $refreshToken)
{
	global $pv, $fv;

	$data = [
		'refresh_token' => $refreshToken,
		'grant_type' => 'refresh_token',
		'redirect_uri' => SCRIPT_URI,
		'client_id' => $clientId,
		'client_secret' => $clientSecret,
	];

	$pv['STEP'] = 'CALLBACK';
	$pv['api_key'] = $apiKey;
	$pv['state_decoded'] = $data;

	$response = v4Post($apiKey, 'oauth/token', $data);

	$accessToken = $fv['access_token'] = $response['access_token'];
	$refreshToken = $fv['refresh_token'] = $response['refresh_token'];

	// get user session: proof the new bearer token works
	$response = v4Get($apiKey, 'user/session', $accessToken);
	if (!isset($response['data']['attributes']['user_id'])) {
		throw new Exception('Error getting user session: ' . json_encode($response));
	}
	$session = $response['data']['attributes'];

	$pv['SESSION'] = $session;
}
