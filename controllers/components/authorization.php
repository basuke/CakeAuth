<?php

class AuthorizationComponent extends Object {
	protected $controller;
	protected $action;
	protected $modelClass;
	
	public function initialize($controller, $settings = array()) {
		$this->controller = $controller;
		$this->modelClass = $controller->modelClass;
	}
	
	public function startup($controller) {
	}
	
	public function shutdown($controller) {
	}
	
	public function authorize($requester, $target = null) {
		$result = $this->isAuthorized($requester, $target);
		if ($result === true) {
			return true;
		}
		
		if ($result === false) {
			$this->controller->cakeError('error403');
		}
		
		trigger_error(sprintf(
			__('%sController::isAuthorized() is not defined.', true), $controller->name
		), E_USER_WARNING);
		
		return false;
	}
	
	public function isAuthorized($requester, $target = null) {
		$controller = $this->controller;
		$action = $controller->action;
		
		if (is_object($target) and method_exists($target, 'isAuthorized')) {
			$result = $target->isAuthorized($requester, $action);
			if ($result !== null) return $result;
		}
		
		$Model = $this->getModel();
		if ($Model) {
			try {
				$result = $Model->isAuthorized($requester, $target, $action);
				if ($result !== null) return $result;
			} catch (Exception $e) {
			}
		}
		
		try {
			$result = $controller->isAuthorized($requester, $target, $action);
			if ($result !== null) return $result;
		} catch (Exception $e) {
		}
	}
	
	protected function getModel() {
		if (empty($this->controller->{$this->modelClass})) return null;
		return $this->controller->{$this->modelClass};
	}
}

