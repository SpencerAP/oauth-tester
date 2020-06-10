<?php
// FIXME: hack hack hack! annoying we have to use v3 at all.
// either build a v4 user/session endpoint or add v3 key to the form.
require_once 'v3key.php';

define('SCRIPT_URI', 'https://spencerponte.com/test/ps/oauth/');

define('PS_URL_BASE', 'https://www.photoshelter.com/');
define('CIPHER', 'AES-128-CBC');

global $fv, $pv;

$pv['ERROR'] = null;
$pv['STEP'] = null;
$pv['SESSION'] = [];

function handleSetCookie($name, $value)
{
	$scheme = parse_url(SCRIPT_URI, PHP_URL_SCHEME);
	$path = parse_url(SCRIPT_URI, PHP_URL_PATH);
	$host = parse_url(SCRIPT_URI, PHP_URL_HOST);

	$expires = 0;
	$secure = ($scheme === 'https') ? true : false;
	$httponly = true;

	setcookie(
		$name,
		$value,
		$expires,
		$path,
		$host,
		$secure,
		$httponly
	);
}

function getBaseUrl()
{
	$baseUrl = $_COOKIE['base_url'] ?? PS_URL_BASE;

	// make sure it ends in a slash
	if (substr($baseUrl, -1) !== '/') {
		$baseUrl .= '/';
	}

	return $baseUrl;
}

function encryptState($plaintext)
{
	$seed = $_COOKIE['encryption_seed'];
	$key = hash_hmac('sha512', $seed, $seed);

	$ivlen = openssl_cipher_iv_length(CIPHER);
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext_raw = openssl_encrypt($plaintext, CIPHER, $key, OPENSSL_RAW_DATA, $iv);
	$iv_and_ciphertext_raw = $iv.$ciphertext_raw;
	$ciphertext = base64_encode($iv_and_ciphertext_raw);

	return $ciphertext;
}

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

function v4Get($apiKey, $endpoint)
{
	return v4Request('GET', $apiKey, $endpoint);
}

function v4Post($apiKey, $endpoint, $data = null)
{
	return v4Request('POST', $apiKey, $endpoint, $data);
}

function v4Request($method, $apiKey, $endpoint, $data = null)
{
	$data = $data ?? [];
	$baseUrl = getBaseUrl() . 'psapi/v4.0/';
	$url = $baseUrl . $endpoint;
	$headers = [
		'Accept: application/json',
		'X-PS-Api-Key: ' . $apiKey,
	];

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
		throw new Exception('CODE: ' . $responseCode . '; ERROR: ' . $curlError . '; RETURN: ' . $response . '; URL: ' . $url);
	}

	$response = $response ?? '{}';
	$response = json_decode($response, true);

	return $response;
}

function v3Request($method, $apiKey, $endpoint, $data = null, $token = null)
{
	$data = $data ?? [];
	$baseUrl = getBaseUrl() . 'psapi/v3.0/';
	$url = $baseUrl . $endpoint;
	$headers = [
		'Accept: application/json',
		'X-PS-Api-Key: ' . $apiKey,
	];

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
		throw new Exception('CODE: ' . $responseCode . '; ERROR: ' . $curlError . '; RETURN: ' . $response . '; URL: ' . $url);
	}

	$response = $response ?? '{}';
	$response = json_decode($response, true);

	return $response;
}

function handleAuthorize($action, $apiKey, $clientId, $clientSecret)
{
	global $fv, $pv;

	// allow baseurl override, persist to cookie
	$baseUrl = $_POST['BASE_URL'] ?? getBaseUrl();
	handleSetCookie('base_url', $baseUrl);
	$_COOKIE['base_url'] = $baseUrl;
	$fv['BASE_URL'] = htmlspecialchars($baseUrl);

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
	// just that ApiKeyInvalidException wasn't thrown
	v4Get($apiKey, 'media/AD000JRX1b1BmlQ4');

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

	header('Location: ' . getBaseUrl() . 'psapi/v4.0/oauth/authorize?' . $queryString);
}

function handleState($state)
{
	global $fv, $pv;

	$pv['STEP'] = 'CALLBACK';

	$code = $_GET['code'] ?? null;

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

	// get session
	$response = v3Request('GET', V3_API_KEY, 'mem/user/session', null, $accessToken);
	if (!isset($response['status']) || $response['status'] !== 'ok') {
		throw new Exception('Error getting user session: ' . json_encode($response));
	}

	$session = $response['data']['Session'];

	$pv['SESSION'] = $session;
}

function main()
{
	global $fv, $pv;

	$seed = $_POST['ENCRYPTION_SEED'] ?? null;

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
		setcookie('encryption_seed');
		setcookie('base_url');
		unset($_COOKIE['encryption_seed']);
		unset($_COOKIE['base_url']);
	}

	$seed = $_COOKIE['encryption_seed'] ?? null;
	if (empty($seed)) {
		$seed = bin2hex(random_bytes(32));
		handleSetCookie('encryption_seed', $seed);
		$_COOKIE['encryption_seed'] = $seed;
	}
	$pv['ENCRYPTION_SEED'] = $seed;

	$baseUrl = $_COOKIE['base_url'] ?? null;
	if (empty($baseUrl)) {
		$baseUrl = PS_URL_BASE;
		handleSetCookie('base_url', $baseUrl);
		$_COOKIE['base_url'] = PS_URL_BASE;
	}
	$fv['BASE_URL'] = htmlspecialchars($baseUrl);

	if ($action === 'authorize') {
		return handleAuthorize($action, $apiKey, $clientId, $clientSecret);
	}

	if (!empty($state)) {
		return handleState($state);
	}

	$pv['STEP'] = 'CREDENTIALS';
}


try {
	main();
} catch (Exception $e) {
	$pv['ERROR'] = htmlspecialchars($e->getMessage());
}

?>


<html lang="en-US">
<head>
<title>oauth test</title>
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
	<label for="BASE_URL">Base URL: </label>
	<input type="text" name="BASE_URL" id="BASE_URL" size="40" value="<?php echo($fv['BASE_URL'] ?? null) ?>">
	<br>
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
<dl>
<?php if ($pv['STEP'] === 'CALLBACK'): ?>
	<dt>Grant Code</dt> <dd><?php echo($fv['code']) ?></dd>
	<dt>State (encoded)</dt> <dd><?php echo($fv['state_raw']) ?></dd>
	<dt>State (decoded)</dt> <dd><?php echo($fv['state']) ?></dd>

	<dt>Access Token</dt> <dd><?php echo($fv['access_token']) ?></dd>
	<dt>Refresh Token</dt> <dd><?php echo($fv['refresh_token']) ?></dd>

	<?php foreach($pv['SESSION'] as $name => $value): ?>
		<dt>Session <?php echo($name) ?></dt> <dd><?php echo($value) ?></dd>
	<?php endforeach; ?>

<?php endif; ?>
</dl>

</div>

</body>
</html>
