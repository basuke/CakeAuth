<?php

class AuthComponent extends Object {
	public $components = array('Auth.Authentication', 'Auth.Authorization');
	protected $initialized;
	
	public function initialize($controller, $settings = array()) {
		$this->Authentication->initialize($controller, $settings);
		$this->Authorization->initialize($controller, $settings);
		
		$this->initialized = true;
	}
	
	public function startup($controller) {
		$this->Authentication->startup($controller);
		$this->Authorization->startup($controller);
	}
	
	public function shutdown($controller) {
		$this->Authentication->shutdown($controller);
		$this->Authorization->shutdown($controller);
	}
	
	public function authorize($requester, $target=null) {
		return $this->Authorization->authorize($requester, $target);
	}
	
	public function allow() {
		$args = func_get_args();
		call_user_func_array(array($this->Authentication, 'allow'), $args);
	}
	
	public function deny() {
		$args = func_get_args();
		call_user_func_array(array($this->Authentication, 'deny'), $args);
	}
	
	public function logout() {
		return $this->Authentication->logout();
	}
	
	public function __get($name) {
		if ($this->initialized) {
			if (!empty($this->Authentication) and property_exists($this->Authentication, $name)) {
				return $this->Authentication->{$name};
			}
			
			if (!empty($this->Authorization) and property_exists($this->Authorization, $name)) {
				return $this->Authorization->{$name};
			}
		}
		
		return null;
	}
	
	public function __set($name, $val) {
		if ($this->initialized) {
			if (!empty($this->Authentication) and property_exists($this->Authentication, $name)) {
				$this->Authentication->{$name} = $val;
			}
			
			if (!empty($this->Authorization) and property_exists($this->Authorization, $name)) {
				$this->Authorization->{$name} = $val;
			}
		} else {
			$this->{$name} = $val;
		}
	}
}

