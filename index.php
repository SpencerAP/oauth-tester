<?php

require_once 'config.php';

global $fv, $pv; // globals for pushing data to the template

// initial app state: just show the credentials form;
// `STEP` will get updated to `CALLBACK` by that handler if we're on that step.
$pv['STEP'] = 'CREDENTIALS';
$pv['ERROR'] = null;
$pv['SESSION'] = [];

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
		'V3_API_KEY',
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

function v3Get($apiKey, $endpoint, $token = null)
{
	$data = $data ?? [];
	$baseUrl = PS_URL_BASE . 'psapi/v3.0/';
	$url = $baseUrl . $endpoint;
	$headers = [
		'Accept: application/json',
		'X-PS-Api-Key: ' . $apiKey,
	];

	return apiCall('GET', $url, $data, $headers, $token);
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

	$response = v4Post($apiKey, 'oauth/token', $data);
	$accessToken = $fv['access_token'] = $response['access_token'];
	$refreshToken = $fv['refresh_token'] = $response['refresh_token'];

	// get user session: proof the bearer token works
	$response = v3Get(V3_API_KEY, 'mem/user/session', $accessToken);
	if (!isset($response['status']) || $response['status'] !== 'ok') {
		throw new Exception('Error getting user session: ' . json_encode($response));
	}
	$session = $response['data']['Session'];

	$pv['SESSION'] = $session;
}

function main()
{
	global $fv, $pv;

	configCheck();

	$action = $_POST['ACTION'] ?? null;
	$apiKey = $_POST['API_KEY'] ?? null;
	$clientId = $_POST['CLIENT_ID'] ?? null;
	$clientSecret = $_POST['CLIENT_SECRET'] ?? null;

	$code = $_GET['code'] ?? null;
	$state = $_GET['state'] ?? null;

	$fv['ACTION'] = htmlspecialchars($action);
	$fv['API_KEY'] = htmlspecialchars($apiKey);
	$fv['CLIENT_ID'] = htmlspecialchars($clientId);
	$fv['CLIENT_SECRET'] = htmlspecialchars($clientSecret);

	if ($action === 'reset') {
		handleReset();
	}

	$seed = getSetEncryptionSeed();
	$pv['ENCRYPTION_SEED'] = $seed;

	if ($action === 'authorize') {
		return handleAuthorize($apiKey, $clientId, $clientSecret);
	}

	if (!empty($state)) {
		return handleCallback($state, $code);
	}
}

// lazy error handling
try {
	main();
} catch (Exception $e) {
	$pv['ERROR'] = htmlspecialchars($e->getMessage());
}

?>

<html lang="en-US">
<head>
<title>OAuth Tester</title>
</head>

<body>

<style>
body {
	background: #ebebeb;
	margin: 0;
	padding: 0;
	color: #404040;
}

h1 {
	background: #000;
	color: #fff;
	font-family: sans-serif;
	padding: 10px 25px;
}

h1, h2, h3 {
	font-family: sans-serif;
}

.content {
	margin: 25px;
}

label {
	display: inline-block;
	margin-top: 15px;
}

input[type="submit"] {
	margin: 20px 0;
}

.err-msg {
	background: #db7093;
	padding: 20px;
}

.code {
	background: #c9c7c7;
	padding: 1 3px;
}

dl {
	display: flex;
	flex-flow: row wrap;
	max-width: 1000;
	border: solid #404040;
	border-width: 1px 1px 0 0;
	font-family: monospace;
}
dt {
	flex-basis: 20%;
	padding: 2px 4px;
	background: #404040;
	text-align: right;
	color: #fff;
}
dd {
	flex-basis: 70%;
	flex-grow: 1;
	margin: 0;
	padding: 2px 4px;
	border-bottom: 1px solid #404040;
	word-break: break-word;
}
</style>

<h1>OAuth Tester</h1>

<div class="content">

<!-- error reporting -->
<?php if (!empty($pv['ERROR'])): ?>
<div class="err-msg">
<?php echo $pv['ERROR'] ?>
</div>
<?php endif; ?>

<h2>Usage</h2>

<ol>
<li>Get an API v4 key</li>
<li><a href="https://engineering.photoshelter.com/psapi-v4-doc/#operation/oAuthRegister">Register</a> an OAuth client with a <span class="code">redirect_uri</span> set to <span class="code"><?php echo SCRIPT_URI ?></span></li>
<li>Fill out and submit this form</li>
</ol>

<p>You'll be redirected to the PhotoShelter OAuth delegation form. After granting access, this script will make an API call to grab session data as a way to verify that the grant was successful.</p>

<?php if ($pv['STEP'] === 'CREDENTIALS'): ?>
<form method="post">
	<label for="API_KEY">v4 API Key: </label>
	<input type="text" name="API_KEY" id="API_KEY" size="30" value="<?php echo($fv['API_KEY'] ?? null) ?>">
	<br>
	<label for="CLIENT_ID">OAuth Client ID: </label>
	<input type="text" name="CLIENT_ID" id="CLIENT_ID" size="30" value="<?php echo($fv['CLIENT_ID'] ?? null) ?>">
	<br>
	<label for="CLIENT_SECRET">OAuth Client Secret: </label>
	<input type="text" name="CLIENT_SECRET" id="CLIENT_SECRET" size="40" value="<?php echo($fv['CLIENT_SECRET'] ?? null) ?>">
	<br>
	<input type="hidden" name="ACTION" id="ACTION" value="authorize">
	<input type="submit" value="Authorize">
</form>
<?php endif; ?>

<form method="post" action="<?php echo SCRIPT_URI ?>">
	<input type="hidden" name="ACTION" id="ACTION" value="reset">
	<input type="submit" value="Reset">
</form>

<!-- debugger -->
<?php if ($pv['STEP'] === 'CALLBACK'): ?>
<dl>
	<dt>Grant Code</dt> <dd><?php echo($fv['code']) ?></dd>
	<dt>State (encoded)</dt> <dd><?php echo($fv['state_raw']) ?></dd>
	<dt>State (decoded)</dt> <dd><?php echo($fv['state']) ?></dd>

	<dt>Access Token</dt> <dd><?php echo($fv['access_token']) ?></dd>
	<dt>Refresh Token</dt> <dd><?php echo($fv['refresh_token']) ?></dd>

	<?php foreach($pv['SESSION'] as $name => $value): ?>
		<dt>Session <?php echo($name) ?></dt> <dd><?php echo($value) ?></dd>
	<?php endforeach; ?>
</dl>
<?php endif; ?>


</div>

</body>
</html>
