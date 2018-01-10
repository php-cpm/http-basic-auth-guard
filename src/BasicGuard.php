<?php
/**
 * This file is part of Http Basic Auth Guard.
 *
 * modified  by zouyi from his version:
 * (c) Christopher Lass <arubacao@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Phpcpm\BasicAuth;

use Illuminate\Auth\Events;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\SupportsBasicAuth;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class BasicGuard implements Guard, SupportsBasicAuth
{
    use GuardHelpers;
    /**
     * The name of the Guard.
     *
     * Corresponds to driver name in authentication configuration.
     *
     * @var string
     */
    protected $name;
    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;
    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;
    /**
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;
    /**
     * Indicates if a token user retrieval has been attempted.
     *
     * @var bool
     */
    protected $tokenRetrievalAttempted = false;

    /**
     * Create a new authentication guard.
     *
     * @param  string $name
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Illuminate\Http\Request $request
     *
     * @return void
     */
    public function __construct($name, UserProvider $provider, Request $request)
    {
        $this->name = $name;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately.
        if (! is_null($this->user)) {
            return $this->user;
        }
        $this->onceBasic();

        return $this->user;
    }

    /**
     * Log a user into the application without sessions or cookies.
     *
     * @param array $credentials
     *
     * @return bool
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false, false);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     *
     * @param string $field
     * @param array $extraConditions
     *
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function basic($field = 'api_key', $extraConditions = [])
    {
        return $this->onceBasic($field, $extraConditions);
    }

    /**
     * Perform a stateless HTTP Basic login attempt.
     *
     * @param string $field
     * @param array $extraConditions
     *
     * @return \Symfony\Component\HttpFoundation\Response|null
     */
    public function onceBasic($field = 'api_key', $extraConditions = [])
    {
        $credentials = $this->getBasicCredentials($this->getRequest(), $field);
        if (! $this->once(array_merge($credentials, $extraConditions))) {
            return $this->getBasicResponse();
        }
    }

    /**
     * Get the credential array for a HTTP Basic request.
     *
     * @param \Illuminate\Http\Request $request
     * @param string $field
     *
     * @return array
     */
    protected function getBasicCredentials(Request $request, $field)
    {
        $user = $request->getUser();

        if (! $user
            && isset($_SERVER['HTTP_AUTHORIZATION'])
            && strpos($_SERVER['HTTP_AUTHORIZATION'], 'Bearer') === 0
        ) {
            $user = trim(str_ireplace('Bearer', '', $_SERVER['HTTP_AUTHORIZATION']));
        }

        return [$field => $user, 'password' => $request->getPassword()];
    }

    /**
     * Get the response for basic authentication.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    protected function getBasicResponse()
    {
        $headers = ['WWW-Authenticate' => 'Basic'];

        return new Response('Invalid credentials.', 401, $headers);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param bool $remember
     * @param bool $login
     *
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false, $login = true)
    {

        $this->fireAttemptEvent($credentials, $remember, $login);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            return true;
        }

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     * @param array $credentials
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        //只验证secret存在
        return ! is_null($user);
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param array $credentials
     * @param bool $remember
     * @param bool $login
     *
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $remember, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Attempting($credentials, $remember, $login));
        }
    }

    /**
     * Register an authentication attempt event listener.
     *
     * @param mixed $callback
     *
     * @return void
     */
    public function attempting($callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Events\Attempting::class, $callback);
        }
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     *
     * @return bool
     */
    public function onceUsingId($id)
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Get the event dispatcher instance.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function getDispatcher()
    {
        return $this->events;
    }

    /**
     * Set the event dispatcher instance.
     *
     * @param \Illuminate\Contracts\Events\Dispatcher $events
     *
     * @return void
     */
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @return \Illuminate\Contracts\Auth\UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     *
     * @return void
     */
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return \Illuminate\Http\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }
}
