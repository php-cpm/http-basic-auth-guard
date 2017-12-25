# HTTP Basic Auth Guard
[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Total Downloads][ico-downloads]][link-downloads]


This is a modified version of HTTP Basic Auth Guard, provided for api auth.

when I readed Pingxx's documents, They tell me the APIs should be authed by basic auth and leave password empty,then I found their php SDK use bearer Token way

so I make my own version middleware to sovle this problem.

As stateless APIs, each time request, we need to verify a token called `API Secret`.

so parse the request Header to get a token, verify it through Model and get Info from db.

## Installation

### Pull in package

```bash
$ composer require php-cpm/http-basic-auth-guard
```

### Read & Follow Documentation

[Authentication](https://lumen.laravel.com/docs/5.2/authentication)

*Important*:
> Before using Lumen's authentication features, you should uncomment the call to register the `AuthServiceProvider` service provider in your `bootstrap/app.php` file.  
> If you would like to use `Auth::user()` to access the currently authenticated user, you should uncomment the `$app->withFacades()` method in your `bootstrap/app.php` file.

### Add the Service Provider

Open `bootstrap/app.php` and register the service provider:

```php
$app->register(Phpcpm\BasicAuth\BasicGuardServiceProvider::class);
```

### Setup Guard Driver

> **Note:** In Lumen you first have to copy the config file from the directory `vendor/laravel/lumen-framework/config/auth.php`, create a `config` folder in your root folder and finally paste the copied file there.

Open your `config/auth.php` config file.  
In `guards` add a new key of your choice (`api` in this example).  
Add `basic` as the driver.  
Make sure you also set `provider` for the guard to communicate with your database.

```php
// config/auth.php
'guards' => [
    'api' => [
        'driver' => 'basic',
        'provider' => 'users'
    ],

    // ...
],

'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model'  => App\User::class,
    ],
],
```

### Middleware Usage
Middleware protecting the route:

```php
Route::get('api/whatever', ['middleware' => 'auth:api', 'uses' => 'NiceController@awesome']);
```

Middleware protecting the controller:

```php
<?php

namespace App\Http\Controllers;

class NiceController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }
}
```

## Change log
Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Contributing
Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

Any issues, feedback, suggestions or questions please use issue tracker [here](https://github.com/php-cpm/http-basic-auth-guard/issues).

## Security
If you discover any security related issues, please email arubacao@gmail.com instead of using the issue tracker.

## License
The MIT License (MIT).