<?php

require_once 'src.php';

global $fv, $pv; // globals for pushing data to the template

// initial app state: just show the credentials form;
// `STEP` will get updated to `CALLBACK` by that handler if we're on that step.
$pv['STEP'] = 'CREDENTIALS';
$pv['ERROR'] = null;
$pv['SESSION'] = [];

// lazy error handling
try {
	main();
} catch (Exception $e) {
	$pv['ERROR'] = htmlspecialchars($e->getMessage());
}

?>
<!DOCTYPE html>
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
	margin-top: 0;
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

<?php if ($pv['STEP'] === 'CREDENTIALS'): ?>

<p>You'll be redirected to the PhotoShelter OAuth delegation form. After granting access, this script will make an API call to grab session data as a way to verify that the grant was successful.</p>

<!-- authorize form -->
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

<?php if ($pv['STEP'] === 'CALLBACK'): ?>

<p>Click refresh to exchange your refresh token for a new access token.</p>

<!-- refresh form -->
<form method="post" action="<?php echo SCRIPT_URI ?>">
	<input type="hidden" name="ACTION" id="REFRESH-ACTION" value="refresh">
	<input type="hidden" name="REFRESH_TOKEN" value="<?php echo($fv['refresh_token']) ?>">
	<input type="hidden" name="CLIENT_ID" value="<?php echo($pv['state_decoded']['client_id']) ?>">
	<input type="hidden" name="CLIENT_SECRET" value="<?php echo($pv['state_decoded']['client_secret']) ?>">
	<input type="hidden" name="API_KEY" value="<?php echo($pv['api_key']) ?>">
	<input type="submit" value="Refresh">
</form>
<?php endif; ?>

<!-- reset form -->
<form method="post" action="<?php echo SCRIPT_URI ?>">
	<input type="hidden" name="ACTION" id="ACTION" value="reset">
	<input type="submit" value="Reset">
</form>

<?php if ($pv['STEP'] === 'CALLBACK'): ?>
<!-- debugger -->
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

<p>Source: <a href="https://github.com/SpencerAP/oauth-tester">SpencerAP/oauth-tester</a></p>

</body>
</html>
