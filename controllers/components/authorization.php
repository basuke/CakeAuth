<?php

class AuthorizationComponent extends Object {
	protected $controller;
	protected $action;
	protected $modelClass;
	
	public function initialize($controller, $settings = array()) {
	}
	
	public function startup($controller) {
		$this->controller = $controller;
		$this->modelClass = $controller->modelClass;
	}
	
	public function shutdown($controller) {
	}
	
	public function authorize($requester, $target = null) {
		$result = $this->isAuthorized($requester, $target);
		if ($result === true) {
			return true;
		}
		
		if ($result === false) {
			$this->controller->cakeError(403);
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
			$result = $target->isAuthorized($requester, $controller, $action);
			if ($result !== null) return $result;
		}
		
		$Model = $this->getModel();
		if ($Model) {
			try {
				$result = $Model->isAuthorized($requester, $controller, $action);
				if ($result !== null) return $result;
			} catch (Exception $e) {
			}
		}
		
		try {
			$result = $controller->isAuthorized();
			if ($result !== null) return $result;
		} catch (Exception $e) {
		}
	}
	
	protected function getModel() {
		if (empty($this->{$this->modelClass})) return null;
		return $this->{$this->modelClass};
	}
}

