<?php defined('SYSPATH') or die ('No direct script access.');

/**
 * Another ACL
 *
 * @see			http://github.com/banks/aacl
 * @package		AACL
 * @uses		Auth
 * @uses		Jelly
 * @author		Paul Banks
 * @copyright	(c) Paul Banks 2010
 * @license		MIT
 */
abstract class AACL_Core
{
	public static $model_role_classname = 'Model_Role';
	public static $model_role_tablename = 'role';
	public static $model_rule_classname = 'Model_AACL_Rule';
	public static $model_rule_tablename = 'aacl_rule';
	public static $model_user_classname = 'Model_User';


	/**
	 * All rules that apply to the currently logged in user
	 *
	 * @var	array	contains AACL::$model_rule_classname objects
	 */
	protected $_rules;

	/**
	 * Returns the currently logged in user
	 *
	 * @return AACL::$model_user_classname|NULL logged in user's instance or NULL pointer
	 */
	public function get_loggedin_user()
	{
		return Auth::instance()->get_user();
	}


	/**
	 * Grant access to $role for resource
	 *
	 * @param	string|Model_Role	string role name or Model_Role object [optional]
	 * @param	string	resource identifier [optional]
	 * @param	string	action [optional]
	 * @param	string	condition [optional]
	 * @return 	void
	 */
	public function grant($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
	{
      // if $role is null — we grant this to everyone
      if( is_null($role) )
      {
        // Create rule
        $this->create_rule(
          array(
            'role'      => NULL,
            'resource'  => $resource,
            'action'    => $action,
            'condition' => $condition,
         ));
      }
      else
      {
         // Normalise $role
         $role = $this->normalise_role($role);

         // Check role exists
         if ( ! $role->loaded())
         {
            throw new AACL_Exception('Unknown role :role passed to AACL::grant()',
               array(':role' => $role->name));
         }

         // Create rule
         $this->create_rule(
          array(
            'role'      => $role,
            'resource'  => $resource,
            'action'    => $action,
            'condition' => $condition,
          )
         );
      }
	}

	/**
	 * Revoke access to $role for resource
    * CHANGED: now accepts NULL role
	 *
	 * @param	string|Model_Role role name or Model_Role object [optional]
	 * @param	string	resource identifier [optional]
	 * @param	string	action [optional]
	 * @param	string	condition [optional]
	 * @return 	void
	 */
	public function revoke($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
	{
      if( is_null($role) )
      {
         $model = Jelly::factory(AACL::$model_rule_tablename, array(
            'role' => NULL,
         ));
      }
      else
      {
         // Normalise $role
         $role = $this->normalise_role($role);

         // Check role exists
         if ( ! $role->loaded())
         {
            // Just return without deleting anything
            return;
         }

         $model = Jelly::factory(AACL::$model_rule_tablename, array(
            'role' => $role->id,
         ));
      }

      if ( ! is_null($resource) )
      {
         // Add normal resources, resource NULL will delete all rules
         $model->resource = $resource;
      }

      if ( ! is_null($resource) && ! is_null($action))
      {
         $model->action = $action;
      }

      if ( ! is_null($resource) && ! is_null($condition))
      {
         $model->condition = $condition;
      }

      // Delete rule
      $model->delete();
	}

   /**
	 * Checks user has permission to access resource
    * CHANGED: now works with unauthorized users
	 *
	 * @param	AACL_Resource	AACL_Resource object being requested
	 * @param	string			action identifier [optional]
	 * @throw	AACL_Exception	To identify permission or authentication failure
	 * @return	void
	 */
	public function check(AACL_Resource $resource, $action = NULL)
	{
		$user = $this->get_loggedin_user();

      // User is logged in, check rules
		$rules = $this->_get_rules($user);

		foreach ($rules as $rule)
		{
			if ($rule->allows_access_to($user, $resource, $action))
			{
				// Access granted, just return
				return true;
			}
		}

      // No access rule matched
      if( $user )
   		throw new AACL_Exception_403;
		else
			throw new AACL_Exception_401;
	}


  /**
   * Create an AACL rule
   *
   * @param array $fields optional fields' values
   *
   * @return NULL
   */
  public function create_rule(array $fields = array())
  {
    Jelly::factory(AACL::$model_rule_tablename)->set($fields)->create();
  }


	/**
	 * Get all rules that apply to user
    * CHANGED
	 *
	 * @param 	AACL::$model_user_classname|AACL::$model_role_classname|bool 	User, role or everyone
	 * @param 	bool		[optional] Force reload from DB default FALSE
	 * @return 	array
	 */
	protected function _get_rules( $user = false, $force_load = FALSE)
	{
      if ( ! isset($this->_rules) || $force_load)
      {
         $select_query = Jelly::query(AACL::$model_rule_tablename);
         // Get rules for user
         if ($user instanceof AACL::$model_user_classname and $user->loaded())
         {
            $select_query->where('role','IN', $user->roles->as_array(NULL, 'id'));
         }
         // Get rules for role
         elseif ($user instanceof AACL::$model_role_classname and $user->loaded())
         {
            $select_query->where('role','=', $user->id);
         }
         // User is guest
         else
         {
            $select_query->where('role','=', null);
         }

         $rules = $select_query
                           ->order_by('LENGTH("resource")', 'ASC')
                           ->execute();

         $this->_rules = array();
         foreach ($rules as $rule)
         {
           $this->_rules[] = $rule;
         }
      }
      return $this->_rules;
	}

	protected $_resources;

	/**
	 * Returns a list of all valid resource objects based on the filesstem adn
    * FIXED
	 *
	 * @param	string|bool	string resource_id [optional] if provided, the info for that specific resource ID is returned,
	 * 					if TRUE a flat array of just the ids is returned
	 * @return	array
	 */
	public function list_resources($resource_id = FALSE)
	{
		if ( ! isset($this->_resources))
		{
			// Find all classes in the application and modules
			$classes = $this->_list_classes();

			// Loop throuch classes and see if they implement AACL_Resource
			foreach ($classes as $i => $class_name)
			{
				$class = new ReflectionClass($class_name);

				if ($class->implementsInterface('AACL_Resource'))
				{
					// Ignore interfaces and abstract classes
					if ($class->isInterface() || $class->isAbstract())
					{
						continue;
					}

					// Create an instance of the class
					$resource = $class->getMethod('acl_instance')->invoke($class_name, $class_name);

               // Get resource info
					$this->_resources[$resource->acl_id()] = array(
						'actions' 		=> $resource->acl_actions(),
						'conditions'	=> $resource->acl_conditions(),
					);

				}

				unset($class);
			}
		}

		if ($resource_id === TRUE)
		{
			return array_keys($this->_resources);
		}
		elseif ($resource_id)
		{
			return isset($this->_resources[$resource_id]) ? $this->_resources[$resource_id] : NULL;
		}

		return $this->_resources;
	}


  /**
   * Normalise role
   *
   * @param AACL::$model_role_classname|string $role role instance or role identifier
   *
   * @return AACL::$model_role_classname role instance
   */
  public function normalise_role($role)
  {
    if ( ! $role instanceof AACL::$model_role_classname)
    {
      return Jelly::query(AACL::$model_role_tablename)->where('name', '=', $role)->limit(1)->execute();
    }

    return $role;
  }


   /**
    * FIXED
    */
	protected function _list_classes($files = NULL)
	{
		if (is_null($files))
		{
			// Remove core module paths form search
			$loaded_modules = Kohana::modules();

			$exclude_modules = array(
               'database',
               'orm',
               'jelly',
               'auth',
               'jelly-auth',
               'userguide',
               'image',
               'codebench',
               'unittest',
               'pagination',
               'migration'
            );

      /*   'firephp' => MODPATH.'firephp',
        'dbforge' => MODPATH.'dbforge',
        'database'   => MODPATH.'database',   // Database access
        'migration' => MODPATH.'migration',
        'formo'        => MODPATH.'formo',
        'formo-jelly'        => MODPATH.'formo-jelly',
        'jelly'        => MODPATH.'jelly',        // Object Relationship Mapping
        'jelly-auth'        => MODPATH.'jelly-auth',
        'auth'       => MODPATH.'auth',       // Basic authentication
        'aacl'       => MODPATH.'aacl',       // Roles, rules, resources
        // 'oauth'      => MODPATH.'oauth',      // OAuth authentication
        // 'pagination' => MODPATH.'pagination', // Paging of results
        'archive' => MODPATH.'archive',
        'unittest'   => MODPATH.'unittest',   // Unit testing
        'userguide'  => MODPATH.'userguide',  // User guide and API documentation
        //'debug-toolbar'        => MODPATH.'debug-toolbar',
        'notices'        => MODPATH.'notices',
        //'editor' => MODPATH.'editor',
        'article' => MODPATH.'article',*/

			$paths = Kohana::include_paths();

         // Remove known core module paths
			foreach ($loaded_modules as $module => $path)
			{
            if (in_array($module, $exclude_modules))
				{
               // Doesn't works properly — double slash on the end
               //	unset($paths[array_search($path.DIRECTORY_SEPARATOR, $paths)]);
               unset($paths[array_search($path, $paths)]);
				}
			}

			// Remove system path
			unset($paths[array_search(SYSPATH, $paths)]);
			$files = Kohana::list_files('classes', $paths);
		}

		$classes = array();

		foreach ($files as $name => $path)
		{
			if (is_array($path))
			{
				$classes = array_merge($classes, $this->_list_classes($path));
			}
			else
			{
				// Strip 'classes/' off start
				$name = substr($name, 8);

				// Strip '.php' off end
				$name = substr($name, 0, 0 - strlen(EXT));

				// Convert to class name
				$classes[] = str_replace(DIRECTORY_SEPARATOR, '_', $name);
			}
		}

		return $classes;
	}

   /**
    * Method, that allows to check any rule from database in any place of project.
    * Works with string presentations of resources, actions, roles and conditions
    * @todo: support conditions
    *
    * @param string $role
    * @param string $resource
    * @param string $action
    * @param string $condition
    * @return bool
    */
   public function granted($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
   {
      $role = Jelly::query(AACL::$model_role_tablename)->where('name','=',$role)->limit(1)->execute();
      $rules = $this->_get_rules($role);

      foreach( $rules as $rule )
      {
         if( $rule->allows_access_to($user, $resource,$action)
                 && $rule->role == $role )
         {
            return true;
         }
      }

      return false;
   }

} // End  AACL_Core