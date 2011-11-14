<?php defined('SYSPATH') or die ('No direct script access.');

/**
 * Access rule model
 *
 * @see			http://github.com/banks/aacl
 * @package		AACL
 * @uses		Auth
 * @uses		Jelly
 * @author		Paul Banks
 * @copyright	(c) Paul Banks 2010
 * @license		MIT
 */
abstract class Model_AACL_Core_Rule extends Jelly_AACL
{
	public static function initialize(Jelly_Meta $meta)
	{
		$meta->table(AACL::$model_rule_tablename)
           ->fields(array(
              'id' => new Jelly_Field_Primary(array(
                 'editable' => false,
              )),
              'role' => new Jelly_Field_BelongsTo(array(
                 'label'   => 'Role',
                 'column'  => 'role_id',
                 'foreign' => AACL::$model_role_tablename.'.id',
              )),
              'resource' => new Jelly_Field_String(array(
                 'label' => 'Controlled resource',
                 'rules' => array(
                     array('max_length', array(':value', 45)),
                 ),
              )),
              'action' => new Jelly_Field_String(array(
                 'label' => 'Controlled action',
                 'rules' => array(
                     array('max_length', array(':value', 45)),
                 ),
              )),
              'condition' => new Jelly_Field_String(array(
                 'label' => 'Access condition',
                 'rules' => array(
                     array('max_length', array(':value', 45)),
                 ),
              )),
            ));
	}

	/**
	 * Check if rule matches current request
    * CHANGED: allows_access_to accepts now resource_id
	 *
   * @param AACL::$model_user_classname User to check rule against
	 * @param string|AACL_Resource	AACL_Resource object or it's id that user requested access to
	 * @param string        action requested [optional]
   * @param bool          bypass condition ?
	 * @return
	 */
	public function allows_access_to($actor, $resource, $action = NULL, $bypass_condition = FALSE)
	{
      if (empty($this->resource))
      {
         // No point checking anything else!
         return TRUE;
      }

      if( $resource instanceof AACL_Resource)
      {
         if (is_null($action))
         {
            // Check to see if Resource whats to define it's own action
            $action = $resource->acl_actions(TRUE);
         }

         // Get string id
         $resource_id = $resource->acl_id();
      }
      else
      {
         // $resource should be valid resource id

         // Get string id
         $resource_id = $resource;
      }

      // Make sure action matches
      if ( ! is_null($action) AND ! empty($this->action) AND $action !== $this->action)
      {
         // This rule has a specific action and it doesn't match the specific one passed
         return FALSE;
      }

      $matches = FALSE;

      // Make sure rule resource is the same as requested resource, or is an ancestor
      while( ! $matches)
      {
         // Attempt match
         if ($this->resource === $resource_id)
         {
            // Stop loop
            $matches = TRUE;
         }
         else
         {
            // Find last occurence of '.' separator
            $last_dot_pos = strrpos($resource_id, '.');

            if ($last_dot_pos !== FALSE)
            {
               // This rule might match more generally, try the next level of specificity
               $resource_id = substr($resource_id, 0, $last_dot_pos);
            }
            else
            {
               // We can't make this any more general as there are no more dots
               // And we haven't managed to match the resource requested
               return FALSE;
            }
         }
      }

      if (is_string($resource))
      {
        $class_name = $resource;
       $class_name = preg_replace('/^m:/', 'Model_', $class_name);
       $class_name = preg_replace('/^c:/', 'Controller_', $class_name);

       $class = new ReflectionClass($class_name);

       if ( ! $class->implementsInterface('AACL_Resource'))
       {
         throw new AACL_Exception(
          'Can\'t check access: class :classname does not implement interface AACL_Resource',
          array(':classname' => $class_name)
         );
       }

       if ($class->isInterface())
       {
         throw new AACL_Exception(
          'Can\'t check access: class :classname is an interface',
          array(':classname' => $class_name)
         );
       }

       if ($class->isAbstract())
       {
         throw new AACL_Exception(
          'Can\'t check access: class :classname is abstract',
          array(':classname' => $class_name)
         );
       }
        // Create an instance of the class
        $resource = $class->getMethod('acl_instance')->invoke($class_name, $class_name);

        $resource_id = $resource->acl_id();

        // TODO: here could be some buggy stuff
        if (is_null($action))
         {
            // Check to see if Resource whats to define it's own action
            $action = $resource->acl_actions(TRUE);
         }
      }
      // Now we know this rule matches the resource, check any match condition
      if ( ! $bypass_condition
           and ! empty($this->condition)
           and ! $resource->acl_conditions($actor, $this->condition))
      {
         // Condition wasn't met (or doesn't exist)
         return FALSE;
      }

      // All looks rosy!
      return TRUE;
	}

	/**
	 * Override create to remove less specific rules when creating a rule
	 *
	 * @return $this
	 */
	public function create()
	{
      $meta = $this->meta();
      $fields = $meta->fields();
		// Delete all more specifc rules for this role
    $delete = $this->_get_base_query();
    if (isset($this->_changed['role']))
    {
      $delete->where($fields['role']->column, '=', $this->_changed['role']);
    }
    else
    {
      $delete->where($fields['role']->column, '=', NULL);
    }

		// If resource is NULL we don't need any more rules - we just delete every rule for this role
		if ( ! is_null($this->resource) )
		{
			// Need to restrict to roles with equal or more specific resource id
			$delete->where_open()
				->where('resource', '=', $this->resource)
				->or_where('resource', 'LIKE', $this->resource.'.%')
				->where_close();
		}

		if ( ! is_null($this->action))
		{
			// If this rule has an action, only remove other rules with the same action
			$delete->where('action', '=', $this->action);
		}

		if ( ! is_null($this->condition))
		{
			// If this rule has a condition, only remove other rules with the same condition
			$delete->where('condition', '=', $this->condition);
		}

		// Do the delete
		foreach ($delete->execute() as $rule)
		{
				$rule->delete();
		}

		// Create new rule
		parent::save();
	}

	/**
	 * Override Default model actions
	 *
	 * @param	bool	$return_current [optional]
	 * @return	mixed
	 */
	public function acl_actions($return_current = FALSE)
	{
		if ($return_current)
		{
			// We don't know anything about what the user intends to do with us!
			return NULL;
		}

		// Return default model actions
		return array('grant', 'revoke');
	}


	/**
	 * Returns a Jelly query to search for AACL rules
	 *
	 * @return Jelly_Query
	 */
	protected function _get_base_query()
	{
		$query = new Jelly_Request;
		return $query->query(AACL::$model_rule_tablename);
	}

} // End Model_AACL_Core_Rule