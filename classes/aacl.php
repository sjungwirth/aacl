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
class AACL
{
	/**
	 * All rules that apply to the currently logged in user
	 * 
	 * @var	array	contains Model_AACL_Rule objects
	 */
	protected static $_rules;
	
	/**
	 * Grant access to $role for resource
	 * 
	 * @param	mixed	string role name or Model_Role object [optional]
	 * @param	string	resource identifier [optional]
	 * @param	string	action [optional]
	 * @param	string	condition [optional]
	 * @return 	void
	 */
	public static function grant($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
	{
      // if $role is null — we grant this to everyone
      if( is_null($role) )
      {
         // Create rule
         Jelly::factory('aacl_rule', array(
            'role' => null,
            'resource' => $resource,
            'action' => $action,
            'condition' => $condition,
         ))->create();
      }
      else
      {
         // Normalise $role
         if ( ! $role instanceof Model_Role)
         {
            $role = Jelly::select('role')->where('name', '=', $role)->limit(1)->execute();
         }

         // Check role exists
         if ( ! $role->loaded())
         {
            throw new AACL_Exception('Unknown role :role passed to AACL::grant()',
               array(':role' => $role->name));
         }

         // Create rule
         Jelly::factory('aacl_rule', array(
            'role' => $role->id,
            'resource' => $resource,
            'action' => $action,
            'condition' => $condition,
         ))->create();
      }
	}
	
	/**
	 * Revoke access to $role for resource
	 * 
	 * @param	mixed	string role name or Model_Role object [optional]
	 * @param	string	resource identifier [optional]
	 * @param	string	action [optional]
	 * @param	string	condition [optional]
	 * @return 	void
	 */
	public static function revoke($role = NULL, $resource = NULL, $action = NULL, $condition = NULL)
	{
      if( is_null($role) )
      {
         $model = Jelly::factory('aacl_rule', array(
            'role' => NULL,
         ));

         if ($resource !== NULL )
         {
            // Add normal reources, resource NULL will delete all rules
            $model->resource = $resource;
         }

         if ($resource !== NULL AND ! is_null($action))
         {
            $model->action = $action;
         }

         if ($resource !== NULL AND ! is_null($condition))
         {
            $model->condition = $condition;
         }

         // Delete rule
         $model->delete();
      }
      else
      {
         // Normalise $role
         if ( ! $role instanceof Model_Role)
         {
            $role = Jelly::factory('role', array('name' => $role))->load();
         }

         // Check role exists
         if ( ! $role->loaded())
         {
            // Just return without deleting anything
            return;
         }

         $model = Jelly::factory('aacl_rule', array(
            'role' => $role->id,
         ));

         if ($resource !== NULL)
         {
            // Add normal reources, resource '*' will delete all rules for this role
            $model->resource = $resource;
         }

         if ($resource !== NULL AND ! is_null($action))
         {
            $model->action = $action;
         }

         if ($resource !== NULL AND ! is_null($condition))
         {
            $model->condition = $condition;
         }

         // Delete rule
         $model->delete();
      }
	}

   /**
	 * Checks user has permission to access resource
	 *
	 * @param	AACL_Resource	AACL_Resource object being requested
	 * @param	string			action identifier [optional]
	 * @throw	AACL_Exception	To identify permission or authentication failure
	 * @return	void
	 */
	public static function check(AACL_Resource $resource, $action = NULL)
	{
		if ($user = Auth::instance()->get_user())
		{
			// User is logged in, check rules
			$rules = self::_get_rules($user);

			foreach ($rules as $rule)
			{
				if ($rule->allows_access_to($resource, $action))
				{
					// Access granted, just return
					return;
				}
			}

			// No access rule matched
			throw new AACL_Exception_403;
		}
		else
		{
         // User isn't logged in, try to apply some global rules
         $rules = self::_get_rules($user);

			foreach ($rules as $rule)
			{
				if ($rule->allows_access_to($resource, $action))
				{
					// Access granted, just return
					return;
				}
			}

			// User is not logged in and no global rules matched
			throw new AACL_Exception_401;
		}
	}
	
	/**
	 * Get all rules that apply to user
	 * 
	 * @param 	Model_User 	$user
	 * @param 	bool		[optional] Force reload from DB default FALSE
	 * @return 	array
	 */
	protected static function _get_rules( $user = false, $force_load = FALSE)
	{
      if( $user instanceof Model_User && !is_null($user->id()))
      {
         if ( ! isset(self::$_rules) OR $force_load)
         {
            self::$_rules = Jelly::select('aacl_rule')
                        ->where('role','IN', $user->roles->as_array(NULL, 'id'))
                        ->order_by('LENGTH("resource")', 'ASC')
                        ->execute();
         }

         return self::$_rules;
      }
      else
      {
         if ( ! isset(self::$_rules) OR $force_load)
         {
            self::$_rules = Jelly::select('aacl_rule')
                        ->where('role','=', null)
                        ->order_by('LENGTH("resource")', 'ASC')
                        ->execute();
         }

         return self::$_rules;
      }
	}
	
	protected static $_resources;
	
	/**
	 * Returns a list of all valid resource objects based on the filesstem adn reflection
	 * 
	 * @param	mixed	string resource_id [optional] if provided, the info for that specific resource ID is returned, 
	 * 					if TRUE a flat array of just the ids is returned
	 * @return	array 
	 */
	public static function list_resources($resource_id = FALSE)
	{		
		if ( ! isset(self::$_resources))
		{
			// Find all classes in the application and modules
			$classes = self::_list_classes();

      
			// Loop throuch classes and see if they implement AACL_Resource
			foreach ($classes as $i => $class_name)
			{
				$class = new ReflectionClass($class_name);

				if ($class->implementsInterface('AACL_Resource'))
				{
					// Ignore interfaces
					if ($class->isInterface())
					{
						continue;
					}
					
					// Ignore abstract classes
					if ($class->isAbstract())
					{
						continue;
					}
	
					// Create an instance of the class
					$resource = $class->getMethod('acl_instance')->invoke($class_name, $class_name);
					
               // Get resource info
					self::$_resources[$resource->acl_id()] = array(
						'actions' 		=> $resource->acl_actions(),
						'conditions'	=> $resource->acl_conditions(),
					);
					
				}
				
				unset($class);
			}			
		}
		
		if ($resource_id === TRUE)
		{
			return array_keys(self::$_resources);
		}
		elseif ($resource_id)
		{
			return isset(self::$_resources[$resource_id]) ? self::$_resources[$resource_id] : NULL;
		}
		
		return self::$_resources;
	}
	
	protected static function _list_classes($files = NULL)
	{
		if (is_null($files))
		{
			// Remove core module paths form search
			$loaded_modules = Kohana::modules();
			
			$exclude_modules = array('database', 'orm', 'jelly', 'auth', 'jelly-auth',
				'userguide', 'image', 'codebench', 'unittest', 'pagination');
				
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
				$classes = array_merge($classes, self::_list_classes($path));
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
   
   protected static $_access_map;

   public static function granted($check_role = NULL, $check_resource = NULL, $check_action = NULL)
   {
      if( !isset(self::$_access_map))
      {
         $map = array();
         $roles = Jelly::select('role')->execute();
         $resources = self::list_resources();
         $rules = Jelly::select('aacl_rule')
                                 ->execute();

         
         // Create map
         foreach( $roles as $role )
         {
            $map[$role->name] = array();
            foreach( $resources as $resource => $sub)
            {
               $map[$role->name][$resource] = array();
               foreach( $sub['actions'] as $action )
               {
                  $map[$role->name][$resource][$action]=false;
                  
                  foreach($rules as $rule)
                  {
                     if( $rule->allows_access_to($resource,$action)
                      && ($rule->role->id == $role->id || is_null($rule->role->id) ) )
                     {
                        $map[$role->name][$resource][$action] = true;
                     }
                  }
               }
            }
         }
         
         self::$_access_map = $map;
      }

      if( is_null($check_action) )
      {
         $ret = true;
         foreach( self::$_access_map[$check_role][$check_resource] as $each )
            if(!$each)
               $ret = false;

         return $ret;
      }
      else
         return self::$_access_map[$check_role][$check_resource][$check_action];
   }
	
	/**
	 * Force static access
	 * 
	 * @return	void 
	 */
	protected function __construct() {}
	
	/**
	 * Force static access
	 * 
	 * @return	void 
	 */
	protected function __clone() {}
	
} // End  AACL