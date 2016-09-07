<?php
/**
 * This command adds username/password authentication to Terminus.
 * 
 * User/pass authentication has been deprecated in favor of the more secure
 * machine token authentication. Support for passwords will be removed at some
 * point in the future. Do not use this method of authentication unless except
 * while transitioning to machine tokens.
 * 
 * This command can be invoked by running `terminus auth upw`
 */

namespace Terminus\Commands;

use Terminus\Commands\TerminusCommand;
use Terminus\Config;
use Terminus\Models\Auth;
use Terminus\Session;
use Terminus\Request;


/**
 * Say hello to the user
 * 
 * @command auth
 */
class AuthUserPasswordCommand extends TerminusCommand {

  /**
   * Authenticate with email/password
   */
  public function upw($args, $assoc_args) {
    $config = Config::getAll();
    if (!empty($args)) {
      $email = array_shift($args);
    }
    if (isset($email) && isset($assoc_args['password'])) {
      // Log in via username and password, if present.
      $password = $assoc_args['password'];
      $this->logInViaUsernameAndPassword(
        $email,
        $assoc_args['password']
      );
      $this->log()->info('Logged in as {email}.', compact('email'));
      $this->log()->log('warn', 'Authenticating with a password is deprecated. Please consider switching to machine tokens.');

      $this->log()->debug(get_defined_vars());
      $this->helpers->launch->launchSelf(
        ['command' => 'art', 'args' => ['fist']]
      );

    }
  }

  /**
   * Execute the login via email/password
   *
   * @param string $email    Email address associated with a Pantheon account
   * @param string $password Password for the account
   * @return bool True if login succeeded
   * @throws TerminusException
   */
  protected function logInViaUsernameAndPassword($email, $password) {
    $options = [
      'form_params' => [
        'email'    => $email,
        'password' => $password,
      ],
      'method' => 'post'
    ];
    try {
      $request = new Request();
      $response = $request->request('authorize', $options);
      if ($response['status_code'] != '200') {
        throw new TerminusException();
      }
    } catch (\Exception $e) {
      throw new TerminusException(
        'Login unsuccessful for {email}', compact('email'), 1
      );
    }

    $session = [
      'user_uuid'           => $response['data']->user_id,
      'session'             => $response['data']->session,
      'session_expire_time' => $response['data']->expires_at,
    ];
    Session::instance()->setData($session);

    return true;
  }

}
