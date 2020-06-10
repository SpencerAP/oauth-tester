# OAuth Tester

Simple form for testing PhotoShelter's OAuth redirect flow.

No secrets are stored on the server; any private data is encrypted in transit using a random seed stored as a temporary cookie in the user's browser.

HTTPS is encouraged.

## Requirements

A webserver with PHP 7.1+

## Usage

* clone into the docroot (or subdirectory thereof) on a server
* `cp config.sample.php config.php`
* fill out `config.php` with appropriate values
* navigate to the script in your browser
* follow the on-screen directions
