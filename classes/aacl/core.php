<?php defined('SYSPATH') or die ('No direct script access.');

/**
 * Another ACL
 *
 * @see			http://github.com/banks/aacl
 * @package		AACL
 * @uses		Auth
 * @uses		ORM
 * @author		Paul Banks
 * @copyright	(c) Paul Banks 2010
 * @license		MIT
 */
abstract class AACL_Core
{
    protected static $_instance = null;

	/**
	 * All rules that apply to the currently logged in user
	 *
	 * @var	array	contains Model_AACL_Rule objects
	 */
	protected $_rules;

    /**
     * @var array
     */
    protected $_resources;

    /**
     * Get singleton instance
     * @return AACL
     */
    public static function get_instance() {
        if (is_null(self::$_instance)) {
            $class_name = __CLASS__;
            self::$_instance = new AACL;
        }
        return self::$_instance;
    }

    protected function __construct() {}
    protected function __clone() {}

    /**
	 * Returns the currently logged in user
	 *
	 * @return Model_User logged in user's instance or NULL pointer
     * @return NULL
	 */
	public function get_loggedin_user()
	{
		return Auth::instance()->get_user();
	}


    /**
     * Grant access to $role for resource
     *
     * @param string|Model_Role    $role string role name or Model_Role object [optional]
     * @param string $resource resource identifier [optional]
     * @param string $action action [optional]
     * @param string $condition condition [optional]
     * @throws AACL_Exception
     * @return void
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
	 * @param	string|Model_Role $role role name or Model_Role object [optional]
	 * @param	string $resource resource identifier [optional]
	 * @param	string $action action [optional]
	 * @param	string $condition condition [optional]
	 * @return 	void
	 */
	public function revoke($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
    {
        $model = ORM::factory('AACL_Rule');

        if( is_null($role))
        {
            $model->where('role', 'IS', NULL);
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

            $model->where('role', '=', $role->id);
        }

        if ( ! is_null($resource) )
        {
            // Add normal resources, resource NULL will delete all rules
            $model->and_where('resource', '=', $resource);

            if (! is_null($action))
            {
                $model->and_where('action', '=', $action);
            }

            if ( ! is_null($condition))
            {
                $model->and_where('condition', '=', $condition);
            }
        }

        $model->find();

        // Delete rule
        if ($model->loaded())
        {
            $model->delete();
        }
	}

    /**
     * Checks user has permission to access resource
     * CHANGED: now works with unauthorized users
     *
     * @param    AACL_Resource $resource AACL_Resource object being requested
     * @param    string $action action identifier [optional]
     * @throws   AACL_Exception To identify permission or authentication failure
     * @return   void
     */
    public function check(AACL_Resource $resource, $action = NULL)
	{
        $user = $this->get_loggedin_user();

        // User is logged in, check rules
        $rules = $this->_get_rules($user);

        /**
         * @var Model_AACL_Rule $rule
         */
		foreach ($rules as $rule)
		{
            if ($rule->allows_access_to($user, $resource, $action))
			{
				// Access granted, just return
				return;
			}
		}

        // No access rule matched
        if ( $user ) {
   		    throw new AACL_Exception_403;
        }
		else {
			throw new AACL_Exception_401;
        }
	}


  /**
   * Create an AACL rule
   *
   * @param array $fields optional fields' values
   *
   * @return void
   */
    public function create_rule(array $fields = array())
    {
        ORM::factory('AACL_Rule')->values($fields)->create();
    }


	/**
	 * Get all rules that apply to user
     *
     * CHANGED
	 *
	 * @param mixed $user Model_User|Model_Role|bool User, role or everyone
	 * @param bool $force_load [optional] Force reload from DB default FALSE
	 * @return Database_Result
	 */
    protected function _get_rules( $user = false, $force_load = FALSE)
	{
        if ( ! isset($this->_rules) || $force_load)
        {
            $select_query = ORM::factory('AACL_Rule');
            // Get rules for user
            if ($user instanceof Model_User and $user->loaded())
            {
                $this->_rules = $select_query->where('role', 'IN', $user->roles->as_array(NULL, 'id'));
            }
            // Get rules for role
            elseif ($user instanceof Model_Role and $user->loaded())
            {
                $this->_rules = $select_query->where('role', '=', $user->id);
            }
            // User is guest
            else
            {
                $this->_rules = $select_query->where('role', '=', null);
            }

            $this->_rules = $select_query
                ->order_by('LENGTH("resource")', 'ASC')
                ->find_all()->as_array();
        }

        return $this->_rules;
    }

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

			// Loop through classes and see if they implement AACL_Resource
			foreach ($classes as $class_name)
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
    * @param Model_Role|string $role role instance or role identifier
    *
    * @return Model_Role role instance
    */
    public function normalise_role($role)
    {
        if ( ! $role instanceof Model_Role)
        {
            return ORM::factory('Role')->where('name', '=', $role)->find();
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
                'auth',
                'userguide',
                'image',
                'codebench',
                'unittest',
                'pagination',
                'migration',
                'simpletest',
                'cache',
                'acl',
                'smarty',
            );

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
			$files = array_merge(Kohana::list_files('classes'.DIRECTORY_SEPARATOR.'controller', $paths), Kohana::list_files('classes'.DIRECTORY_SEPARATOR.'model', $paths));
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
        $role = ORM::factory('Role')->where('name', '=', $role)->find();
        $rules = $this->_get_rules($role);

        /**
         * @var Model_AACL_Rule $rule
         */
        foreach( $rules as $rule )
        {
            if( $rule->allows_access_to($role, $resource, $action) && $rule->role == $role )
            {
                return true;
            }
        }

        return false;
    }

} // End  AACL_Core