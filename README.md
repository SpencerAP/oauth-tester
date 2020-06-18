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

## Legal

"PhotoShelter" is a registered trademark of [PhotoShelter](https://www.photoshelter.com/). References to PhotoShelter in this repository are intended to comply with their [trademark guidelines](https://www.photoshelter.com/support/trademark). 

> Feel free to include language on your site explaining that your application is built on the PhotoShelter platform so people understand your product.

This repository implies no ownership of or license to the PhotoShelter trademark or of PhotoShelter's underlying APIs.

## License

[Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)
