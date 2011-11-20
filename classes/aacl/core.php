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
	protected $_rules_all;
	protected $_rules_per_resource;


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
		$rules = $this->_get_rules($user, FALSE, $resource->acl_id());

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
	 * Get a list of all rules matching criteria
   *
	 * @param AACL::$model_user_classname|AACL::$model_role_classname|NULL $user         user, role or everyone (NULL)
	 * @param bool                                                         $force_reload force reload from DB default FALSE
   * @param string|NULL                                                  $resourceid   full resource ID criterion (NULL matches all resource IDs)
	 *
   * @return array list of matching rules
	 */
	protected function _get_rules($user = NULL, $force_reload = FALSE, $resourceid = NULL)
	{
    if ($force_reload)
    {
      $this->clear_cache();
    }

    if ( ! $this->_are_rules_cached($user, $resourceid))
    {
      if ($user instanceof AACL::$model_user_classname and $user->loaded())
      {
        foreach ($user->roles as $role)
        {
          $this->_fetch_rules($role->id, $resourceid);
        }
      }
      elseif ($user instanceof AACL::$model_role_classname and $user->loaded())
      {
        $this->_fetch_rules($role->id, $resourceid);
      }
      else
      {
        $this->_fetch_rules(0, $resourceid);
      }
    }

    return $this->_cached_rules($user, $resourceid);
  }


  /**
   *
   * @param AACL::$model_user_classname|AACL::$model_role_classname|NULL $user         user, role or noone (NULL)
	 * @param bool                                                         $force_reload force reload from DB default FALSE
   * @param string|NULL                                                  $resourceid   full resource ID criterion (NULL matches all resource IDs)
	 *
   * return bool are matching rules cached ?
   */
  protected function _are_rules_cached($user = NULL, $resourceid = NULL)
  {
    $resource_key = $this->_get_resource_key($resourceid);

    $cached = TRUE;
    if ($user instanceof AACL::$model_user_classname and $user->loaded())
    {
      foreach ($user->roles as $role)
      {
        $role_key = $this->_get_role_key($role->id);
        if ( ! isset($this->_rules[$role_key])
            or ! isset($this->_rules[$role_key][$resource_key]))
        {
          $cached = FALSE;
        }
      }
    }
    elseif ($user instanceof AACL::$model_role_classname and $user->loaded())
    {
      $role_key = $this->_get_role_key($user->id);
      if ( ! isset($this->_rules[$role_key])
          or ! isset($this->_rules[$role_key][$resource_key]))
      {
        $cached = FALSE;
      }
    }
    else
    {
      // Force reload as it's impossible to know if all rules are already in the cache
      $cached = FALSE;
    }

    return $cached;
  }


  /**
   * Fetch all rules from database and cache them
   *
   * @return null
   */
  public function cache_all_rules()
  {
    $this->_fetch_rules(NULL, NULL);
  }


  /**
   * Fetch rules matching criteria and cache them
   *
   * @param int|NULL $roleid     ID of the role criterion (zero matches no role, NULL matches all roles)
   * @param string   $resourceid full resource ID criterion (NULL matches all resource IDs)
   *
   * @return null
   */
  protected function _fetch_rules($roleid = 0, $resourceid = NULL)
  {
    $query = Jelly::query(AACL::$model_rule_tablename);

    if ($roleid === 0)
    {
      $query->where('role','=', NULL);
    }
    elseif ($roleid > 0)
    {
      $query->where('role','=', $roleid);
    }

    if ( ! is_null($resourceid))
    {
      $query->and_where_open()
            ->where('resource','=', '')
            ->or_where('resource','LIKE', $this->_get_resource_key($resourceid).'%')
            ->and_where_close();
    }

    $query->order_by('LENGTH("resource")', 'ASC');

    $rules = $query->execute();

    foreach ($rules as $rule)
    {
      $role_key     = $this->_get_role_key($rule->role->id);
      $resource_key = $this->_get_resource_key($rule->resource);

      if ( ! isset($this->_rules[$role_key]))
      {
        $this->_rules[$role_key] = array();
      }

      if ( ! isset($this->_rules[$role_key][$resource_key]))
      {
        $this->_rules[$role_key][$resource_key] = array();
      }

      $this->_rules[$role_key][$resource_key][] = $rule;
    }
  }


  /**
   * Add rules matching criteria to the given list
   *
   * @param array  &$rules       list of rules to add matching rules to
   * @param string $role_key     key of the role in inner cache
   * @param string $resource_key key of the resource in inner cache
   *
   * @return null
   */
  protected function _add_rules_to_list(array & $rules, $role_key, $resource_key)
  {
    if (isset($this->_rules[$role_key])
        and isset($this->_rules[$role_key][$resource_key]))
    {
      foreach ($this->_rules[$role_key][$resource_key] as $rule)
      {
        $rules[] = $rule;
      }
    }
  }

  /**
   * List of cached rules matching criteria
   *
   * @param AACL::$model_user_classname|AACL::$model_role_classname|NULL $user       user, role or noone (NULL)
   * @param string                                                       $resourceid full resource ID criterion (NULL matches all resource IDs)
   *
   * @return array list of matching rules (more general first)
   */
  protected function _cached_rules($user = NULL, $resourceid = NULL)
  {
    $resource_key = $this->_get_resource_key($resourceid);

    $rules = array();

    $this->_add_rules_to_list($rules, 'global', 'global');
    $this->_add_rules_to_list($rules, 'global', $resource_key);

    if ($user instanceof AACL::$model_user_classname and $user->loaded())
    {
      foreach ($user->roles as $role)
      {
        $role_key = $this->_get_role_key($role->id);
        $this->_add_rules_to_list($rules, $role_key, 'global');
        $this->_add_rules_to_list($rules, $role_key, $resource_key);
      }
    }
    elseif ($user instanceof AACL::$model_role_classname and $user->loaded())
    {
      $role_key = $this->_get_role_key($user->id);
      $this->_add_rules_to_list($rules, $role_key, 'global');
      $this->_add_rules_to_list($rules, $role_key, $resource_key);
    }
    else
    {
      // Noone means no rules
    }

    return $rules;
  }


  /**
   * Get the inner cache resource key of a given resource
   *
   * @param string $resource full resource id
   *
   * @return string resource key
   */
  protected function _get_resource_key($resource)
  {
    $base_resourceid = preg_replace('/\.\d+/', '', $resource);

    if (empty($base_resourceid))
      return 'global';

    return $base_resourceid;
  }


  /**
   * Get the inner cache role key of a given role ID
   *
   * @param int $roleid ID of a role
   *
   * @return string role key
   */
  protected function _get_role_key($roleid)
  {
    if ($roleid == 0)
      return 'global';

    return (string) $roleid;
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