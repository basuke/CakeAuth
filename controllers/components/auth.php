<?php

class AuthComponent extends Object {
	public $components = array('Auth.Authentication', 'Auth.Authorization');
	
	public $data;
	
	public function initialize($controller, $settings = array()) {
		$this->Authentication->initialize($controller, $settings);
		$this->Authorization->initialize($controller, $settings);
	}
	
	public function startup($controller) {
		$this->Authentication->startup($controller);
		$this->data = $this->Authentication->data;
		
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
}

