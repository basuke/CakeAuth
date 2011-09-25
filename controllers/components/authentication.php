<?php

/*
	authorizationを取り除いた
	identifyをdelegate対応
	自動的にcontroller->data[User][password]をハッシュ化しない（コンポーネント側はする）
	userVariableName を追加。コントローラに自動的に設定される
	delegateに filterAuthUser を追加。user()が呼ばれる際にデータをフィルタリングできる
	password:row にハッシュ前のパスワードを渡すように修正
*/

App::import('Core', array('Router', 'Security'), false);

class AuthenticationComponent extends Object {
/**
 * Maintains current user login state.
 *
 * @var boolean
 * @access private
 */
	protected $_loggedIn = false;

/**
 * Other components utilized by AuthComponent
 *
 * @var array
 * @access public
 */
	public $components = array('Session', 'RequestHandler');

/**
 * A reference to the object used for authentication
 *
 * @var object
 * @access public
 * @link http://book.cakephp.org/view/1278/authenticate
 */
	public $authenticate = null;

/**
 * The name of an optional view element to render when an Ajax request is made
 * with an invalid or expired session
 *
 * @var string
 * @access public
 * @link http://book.cakephp.org/view/1277/ajaxLogin
 */
	public $ajaxLogin = null;

/**
 * The name of the element used for SessionComponent::setFlash
 *
 * @var string
 * @access public
 */
	public $flashElement = 'default';

/**
 * The name of the model that represents users which will be authenticated.  Defaults to 'User'.
 *
 * @var string
 * @access public
 * @link http://book.cakephp.org/view/1266/userModel
 */
	public $userModel = 'User';

/**
 * Additional query conditions to use when looking up and authenticating users,
 * i.e. array('User.is_active' => 1).
 *
 * @var array
 * @access public
 * @link http://book.cakephp.org/view/1268/userScope
 */
	public $userScope = array();

/**
 * Allows you to specify non-default login name and password fields used in
 * $userModel, i.e. array('username' => 'login_name', 'password' => 'passwd').
 *
 * @var array
 * @access public
 * @link http://book.cakephp.org/view/1267/fields
 */
	public $fields = array('username' => 'username', 'password' => 'password');

/**
 * The session key name where the record of the current user is stored.  If
 * unspecified, it will be "Auth.{$userModel name}".
 *
 * @var string
 * @access public
 * @link http://book.cakephp.org/view/1276/sessionKey
 */
	public $sessionKey = null;

/**
 * A URL (defined as a string or array) to the controller action that handles
 * logins.
 *
 * @var mixed
 * @access public
 * @link http://book.cakephp.org/view/1269/loginAction
 */
	public $loginAction = null;

/**
 * Normally, if a user is redirected to the $loginAction page, the location they
 * were redirected from will be stored in the session so that they can be
 * redirected back after a successful login.  If this session value is not
 * set, the user will be redirected to the page specified in $loginRedirect.
 *
 * @var mixed
 * @access public
 * @link http://book.cakephp.org/view/1270/loginRedirect
 */
	public $loginRedirect = null;

/**
 * The default action to redirect to after the user is logged out.  While AuthComponent does
 * not handle post-logout redirection, a redirect URL will be returned from AuthComponent::logout().
 * Defaults to AuthComponent::$loginAction.
 *
 * @var mixed
 * @access public
 * @see AuthComponent::$loginAction
 * @see AuthComponent::logout()
 * @link http://book.cakephp.org/view/1271/logoutRedirect
 */
	public $logoutRedirect = null;

/**
 * Error to display when user login fails.  For security purposes, only one error is used for all
 * login failures, so as not to expose information on why the login failed.
 *
 * @var string
 * @access public
 * @link http://book.cakephp.org/view/1272/loginError
 */
	public $loginError = null;

/**
 * Error to display when user attempts to access an object or action to which they do not have
 * acccess.
 *
 * @var string
 * @access public
 * @link http://book.cakephp.org/view/1273/authError
 */
	public $authError = null;

/**
 * Determines whether AuthComponent will automatically redirect and exit if login is successful.
 *
 * @var boolean
 * @access public
 * @link http://book.cakephp.org/view/1274/autoRedirect
 */
	public $autoRedirect = true;

/**
 * Controller actions for which user validation is not required.
 *
 * @var array
 * @access public
 * @see AuthComponent::allow()
 * @link http://book.cakephp.org/view/1251/Setting-Auth-Component-Variables
 */
	public $allowedActions = array();

/**
 * Form data from Controller::$data
 *
 * @var array
 * @access public
 */
	public $data = array();

/**
 * Parameter data from Controller::$params
 *
 * @var array
 * @access public
 */
	public $params = array();

/**
 * Login user variable name to set in controller
 *
 * @var array
 * @access public
 */
	public $userVariableName = 'login_user';
	
/**
 * Method list for bound controller
 *
 * @var array
 * @access protected
 */
	protected $_methods = array();

/**
 * Initializes AuthComponent for use in the controller
 *
 * @param object $controller A reference to the instantiating controller object
 * @return void
 * @access public
 */
	public function initialize($controller, $settings = array()) {
		$this->params = $controller->params;
		$this->_methods = $controller->methods;

		$this->_set($settings);
		
		if (Configure::read() > 0) {
			App::import('Debugger');
			Debugger::checkSecurityKeys();
		}
	}

/**
 * Main execution method.  Handles redirecting of invalid users, and processing
 * of login form data.
 *
 * @param object $controller A reference to the instantiating controller object
 * @return boolean
 * @access public
 */
	public function startup($controller) {
		$this->setControllerUser($controller);
		
		$isErrorOrTests = (
			strtolower($controller->name) == 'cakeerror' or
			(strtolower($controller->name) == 'tests' and Configure::read() > 0)
		);
		if ($isErrorOrTests) {
			return true;
		}

		$methods = array_flip($controller->methods);
		$action = strtolower($controller->params['action']);
		$isMissingAction = (
			$controller->scaffold === false and
			!isset($methods[$action])
		);

		if ($isMissingAction) {
			return true;
		}

		if (!$this->__setDefaults()) {
			return false;
		}

		$this->data = $this->hashPasswords($controller->data);
		$url = '';

		if (isset($controller->params['url']['url'])) {
			$url = $controller->params['url']['url'];
		}
		$url = Router::normalize($url);
		$loginAction = Router::normalize($this->loginAction);

		$allowedActions = array_map('strtolower', $this->allowedActions);
		$isAllowed = (
			$this->allowedActions == array('*') or
			in_array($action, $allowedActions)
		);

		if ($loginAction != $url and $isAllowed) {
			return true;
		}

		if ($loginAction == $url) {
			$model = $this->getModel();
			$alias = $model->alias;
			$username = $this->fields['username'];
			$password = $this->fields['password'];
			$data = $this->data;
			
			if (empty($data[$alias])) {
				if (!$this->Session->check('Auth.redirect') and !$this->loginRedirect and env('HTTP_REFERER')) {
					$this->Session->write('Auth.redirect', $controller->referer(null, true));
				}
				return false;
			}

			if (!empty($data[$alias][$username]) and !empty($data[$alias][$password])) {
				$data = array(
					$alias . '.' . $username => $data[$alias][$username],
					$alias . '.' . $password => $data[$alias][$password]
				);
				
				if ($this->login($data)) {
					if ($this->autoRedirect) {
						$controller->redirect($this->redirect(), null, true);
					}
					
					$this->setControllerUser($controller);
					return true;
				}
			}

			$this->Session->setFlash($this->loginError, $this->flashElement, array(), 'auth');
			$controller->data[$alias][$password] = null;
			return false;
		} else {
			if (!$this->user()) {
				if (!$this->RequestHandler->isAjax()) {
					$this->Session->setFlash($this->authError, $this->flashElement, array(), 'auth');
					if (!empty($controller->params['url']) and count($controller->params['url']) >= 2) {
						$query = $controller->params['url'];
						unset($query['url'], $query['ext']);
						$url .= Router::queryString($query, array());
					}
					$this->Session->write('Auth.redirect', $url);
					$controller->redirect($loginAction);
					return false;
				} elseif (!empty($this->ajaxLogin)) {
					$controller->viewPath = 'elements';
					echo $controller->render($this->ajaxLogin, $this->RequestHandler->ajaxLayout);
					$this->_stop();
					return false;
				} else {
					$controller->redirect(null, 403);
				}
			}
			
			$this->setControllerUser($controller);
		}

		return true;
	}
	
/**
 * Component shutdown.  If user is logged in, wipe out redirect.
 *
 * @param object $controller Instantiating controller
 * @access public
 */
	public function shutdown($controller) {
		if ($this->_loggedIn) {
			$this->Session->delete('Auth.redirect');
		}
	}

/**
 * Attempts to introspect the correct values for object properties including
 * $userModel and $sessionKey.
 *
 * @return boolean
 * @access private
 */
	private function __setDefaults() {
		if (empty($this->userModel)) {
			trigger_error(__("Could not find \$userModel. Please set AuthComponent::\$userModel in beforeFilter().", true), E_USER_WARNING);
			return false;
		}
		list($plugin, $model) = pluginSplit($this->userModel);
		$defaults = array(
			'loginAction' => array(
				'controller' => Inflector::underscore(Inflector::pluralize($model)),
				'action' => 'login',
				'plugin' => Inflector::underscore($plugin),
			),
			'sessionKey' => 'Auth.' . $model,
			'logoutRedirect' => $this->loginAction,
			'loginError' => __('Login failed. Invalid username or password.', true),
			'authError' => __('You are not authorized to access that location.', true)
		);
		foreach ($defaults as $key => $value) {
			if (empty($this->{$key})) {
				$this->{$key} = $value;
			}
		}
		return true;
	}

/**
 * Takes a list of actions in the current controller for which authentication is not required, or
 * no parameters to allow all actions.
 *
 * @param mixed $action Controller action name or array of actions
 * @param string $action Controller action name
 * @param string ... etc.
 * @return void
 * @access public
 * @link http://book.cakephp.org/view/1257/allow
 */
	public function allow() {
		$args = func_get_args();
		if (empty($args) or $args == array('*')) {
			$this->allowedActions = $this->_methods;
		} else {
			if (isset($args[0]) and is_array($args[0])) {
				$args = $args[0];
			}
			$this->allowedActions = array_merge($this->allowedActions, array_map('strtolower', $args));
		}
	}

/**
 * Removes items from the list of allowed actions.
 *
 * @param mixed $action Controller action name or array of actions
 * @param string $action Controller action name
 * @param string ... etc.
 * @return void
 * @see AuthComponent::allow()
 * @access public
 * @link http://book.cakephp.org/view/1258/deny
 */
	public function deny() {
		$args = func_get_args();
		if (isset($args[0]) and is_array($args[0])) {
			$args = $args[0];
		}
		foreach ($args as $arg) {
			$i = array_search(strtolower($arg), $this->allowedActions);
			if (is_int($i)) {
				unset($this->allowedActions[$i]);
			}
		}
		$this->allowedActions = array_values($this->allowedActions);
	}

/**
 * Manually log-in a user with the given parameter data.  The $data provided can be any data
 * structure used to identify a user in AuthComponent::identify().  If $data is empty or not
 * specified, POST data from Controller::$data will be used automatically.
 *
 * After (if) login is successful, the user record is written to the session key specified in
 * AuthComponent::$sessionKey.
 *
 * @param mixed $data User object
 * @return boolean True on login success, false on failure
 * @access public
 * @link http://book.cakephp.org/view/1261/login
 */
	public function login($data = null) {
		$this->__setDefaults();
		$this->_loggedIn = false;

		if (empty($data)) {
			$data = $this->data;
		}

		if ($user = $this->identify($data)) {
			$this->update($user);
			$this->_loggedIn = true;
		}
		return $this->_loggedIn;
	}

/**
 * Logs a user out, and returns the login action to redirect to.
 *
 * @param mixed $url Optional URL to redirect the user to after logout
 * @return string AuthComponent::$loginAction
 * @see AuthComponent::$loginAction
 * @access public
 * @link http://book.cakephp.org/view/1262/logout
 */
	public function logout() {
		$this->__setDefaults();
		$this->Session->delete($this->sessionKey);
		$this->Session->delete('Auth.redirect');
		$this->_loggedIn = false;
		return Router::normalize($this->logoutRedirect);
	}
	
	public function update($user) {
		$this->Session->write($this->sessionKey, $user);
	}
	
/**
 * Get the current user from the session.
 *
 * @param string $key field to retrive.  Leave null to get entire User record
 * @return mixed User record. or null if no user is logged in.
 * @access public
 * @link http://book.cakephp.org/view/1264/user
 */
	public function user($key = null) {
		$this->__setDefaults();
		if (!$this->Session->check($this->sessionKey)) {
			return null;
		}
		
		$user = $this->Session->read($this->sessionKey);
		if ($key == null) {
			$model = $this->getModel();
			return array($model->alias => $user);
		} else {
			if (isset($user[$key])) {
				return $user[$key];
			}
			return null;
		}
	}

/**
 * Get the current user from the session. delegate's filter applied.
 *
 * @return mixed User record. or null if no user is logged in.
 * @access public
 */
	public function filteredUser() {
		$user = $this->user();
		if (!$user) return $user;
		
		if (is_object($this->authenticate) and method_exists($this->authenticate, 'filterAuthUser')) {
			$user = $this->authenticate->filterAuthUser($user);
		}
		
		return $user;
	}

/**
 * If no parameter is passed, gets the authentication redirect URL.
 *
 * @param mixed $url Optional URL to write as the login redirect URL.
 * @return string Redirect URL
 * @access public
 */
	public function redirect($url = null) {
		if (!is_null($url)) {
			$redir = $url;
			$this->Session->write('Auth.redirect', $redir);
		} elseif ($this->Session->check('Auth.redirect')) {
			$redir = $this->Session->read('Auth.redirect');
			$this->Session->delete('Auth.redirect');

			if (Router::normalize($redir) == Router::normalize($this->loginAction)) {
				$redir = $this->loginRedirect;
			}
		} else {
			$redir = $this->loginRedirect;
		}
		return Router::normalize($redir);
	}

/**
 * Returns a reference to the model object specified, and attempts
 * to load it if it is not found.
 *
 * @return object A reference to a model object
 * @access protected
 */
	protected function getModel() {
		$model = ClassRegistry::init($this->userModel);
		
		if (empty($model)) {
			trigger_error(__('Auth::getModel() - Model is not set or could not be found', true), E_USER_WARNING);
			return null;
		}
		
		return $model;
	}

/**
 * Identifies a user based on specific criteria.
 *
 * @param mixed $user Optional. The identity of the user to be validated.
 *              Uses the current user session if none specified.
 * @param array $conditions Optional. Additional conditions to a find.
 * @return array User record data, or null, if the user could not be identified.
 * @access public
 */
	public function identify($user = null, $conditions = null) {
		if ($conditions === false) {
			$conditions = array();
		} elseif (is_array($conditions)) {
			$conditions = array_merge((array)$this->userScope, $conditions);
		} else {
			$conditions = $this->userScope;
		}
		
		$model = $this->getModel();
		$alias = $model->alias;
		$username = $this->fields['username'];
		$password = $this->fields['password'];
		
		if (empty($user)) {
			$user = $this->user();
			if (empty($user)) {
				return null;
			}
		} elseif (is_object($user) and is_a($user, 'Model')) {
			if (!$user->exists()) {
				return null;
			}
			$user = $user->read();
			$user = $user[$alias];
		} elseif (is_array($user) and isset($user[$alias])) {
			$user = $user[$alias];
		}

		if (is_object($this->authenticate) and method_exists($this->authenticate, 'identify')) {
			return $this->authenticate->identify($user, $conditions);
		}
		
		if (is_array($user) and (isset($user[$username]) or isset($user[$alias . '.' . $username]))) {
			if (isset($user[$username]) and !empty($user[$username])  and !empty($user[$password])) {
				if (trim($user[$username]) == '=' or trim($user[$password]) == '=') {
					return false;
				}
				$find = array(
					$alias.'.'.$username => $user[$username],
					$alias.'.'.$password => $user[$password]
				);
			} elseif (isset($user[$alias . '.' . $username]) and !empty($user[$alias . '.' . $username])) {
				if (trim($user[$alias . '.' . $username]) == '=' or trim($user[$alias . '.' . $password]) == '=') {
					return false;
				}
				$find = array(
					$alias.'.'.$username => $user[$alias . '.' . $username],
					$alias.'.'.$password => $user[$alias . '.' . $password]
				);
			} else {
				return false;
			}
			$data = $model->find('first', array(
				'conditions' => array_merge($find, $conditions),
				'recursive' => 0
			));
			if (empty($data) or empty($data[$alias])) {
				return null;
			}
		} elseif (!empty($user) and is_string($user)) {
			$data = $model->find('first', array(
				'conditions' => array_merge(array($model->escapeField() => $user), $conditions),
			));
			if (empty($data) or empty($data[$alias])) {
				return null;
			}
		}

		if (!empty($data)) {
			if (!empty($data[$alias][$password])) {
				unset($data[$alias][$password]);
			}
			return $data[$alias];
		}
		return null;
	}

/**
 * Hash any passwords found in $data using $userModel and $fields['password']
 *
 * @param array $data Set of data to look for passwords
 * @return array Data with passwords hashed
 * @access public
 * @link http://book.cakephp.org/view/1259/hashPasswords
 */
	public function hashPasswords($data) {
		if (is_object($this->authenticate) and method_exists($this->authenticate, 'hashPasswords')) {
			return $this->authenticate->hashPasswords($data);
		}

		if (!is_array($data)) return $data;
		
		$model = $this->getModel();
		$alias = $model->alias;
		$username = $this->fields['username'];
		$password = $this->fields['password'];
		
		if(!empty($data[$alias][$username]) and !empty($data[$alias][$password])) {
			$data[$alias][$password. ':raw'] = $data[$alias][$password];
			$data[$alias][$password] = $this->password($data[$alias][$password]);
		}
		
		return $data;
	}

/**
 * Hash a password with the application's salt value (as defined with Configure::write('Security.salt');
 *
 * @param string $password Password to hash
 * @return string Hashed password
 * @access public
 * @link http://book.cakephp.org/view/1263/password
 */
	public function password($password) {
		if (is_object($this->authenticate) and method_exists($this->authenticate, 'password')) {
			return $this->authenticate->password($password);
		}
		
		return Security::hash($password, null, true);
	}
	
	protected function setControllerUser($controller) {
		$controller->set($this->userVariableName, $this->filteredUser());
	}
}

