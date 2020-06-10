<?php

/**
 * @var string This is the full URL of where this script will live;
 *	it must exactly match the `redirect_uri` registered to the OAuth client.
 *	Ex: https://www.mysite.com/oauth-test/
 *	TODO: consider moving to an external config.
 */
define('SCRIPT_URI', '');

/**
 * @var string This is the URL for PhotoShelter, which will be used to create
 *	which will be used to create full endpoint URLs;
 *	it must include a trailing slash.
 *	Ex: https://www.photoshelter.com/
 *	TODO: consider moving to an external config.
 */
define('PS_URL_BASE', 'https://www.photoshelter.com/');

/**
 * @var string V3 API Key.
 *	FIXME!
 *	Once V4 has its own user/session endpoint
 *	we can get rid of this setting and just use V4.
 */
define('V3_API_KEY', '');

/**
 * @var string Test media ID.
 *	A media-get request is used as a simple check to verify the API key.
 *	Any existing media ID is fine so long as it is publicly accessible.
 */
define('TEST_MEDIA_ID', '');

/**
 * @var string The cipher used to encrypt secret data passed between this script
 *	and PhotoShelter via the `state` parameter. This encryption is done
 *	mainly so that secrets aren't leaked via server access logs or via
 *	middlemen in the event that your server doesn't support HTTPS.
 *	Any cipher supported by your server is fine, see:
 *	https://www.php.net/manual/en/function.openssl-get-cipher-methods.php
 */
define('CIPHER', 'AES-128-CBC');
