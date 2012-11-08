<?php defined('SYSPATH') or die ('No direct script access.');

/**
 * Access rule model
 *
 * @see			http://github.com/banks/aacl
 * @package		AACL
 * @uses		Auth
 * @uses		ORM
 * @author		Paul Banks
 * @copyright	(c) Paul Banks 2010
 * @license		MIT
 */
abstract class Model_AACL_Core_Rule extends ORM_AACL
{
    protected $_table_name = 'modsuite_acl';

    protected $_primary_key = 'id';

    protected $_table_columns = array(
        'id' => array('data_type' => 'int', 'is_nullable' => FALSE),
        'role_id' => array('data_type' => 'int', 'is_nullable' => TRUE),
        'resource' => array('data_type' => 'varchar', 'is_nullable' => FALSE),
        'action' => array('data_type' => 'varchar', 'is_nullable' => FALSE),
        'condition' => array('data_type' => 'varchar', 'is_nullable' => FALSE),
    );

    protected $_belongs_to = array(
        'modsuite_role' => array(
            'model'       => 'Model_Role',
            'foreign_key' => 'role_id',
        ),
    );

    // TODO: validation

	/**
	 * Check if rule matches current request
     * CHANGED: allows_access_to accepts now resource_id
	 *
     * @param Model_User $user AACL instance
	 * @param string|AACL_Resource $resource AACL_Resource object or it's id that user requested access to
	 * @param string $action action requested [optional]
	 * @return
	 */
	public function allows_access_to($user, $resource, $action = NULL)
	{
        if (empty($this->resource))
        {
            // No point checking anything else!
            return TRUE;
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
        }

        if ( ! ($resource instanceof AACL_Resource))
        {
            $type = (is_object($resource) ? get_class($resource) : gettype($resource));

            throw new AACL_Exception(
                'Can\'t check access: resource :type does not implement interface AACL_Resource',
                array(':type' => $type)
            );
        }

        if (is_null($action))
        {
            // Check to see if Resource wants to define it's own action
            $action = $resource->acl_actions(TRUE);
        }

        // Make sure action matches
        if ( ! is_null($action) AND ! empty($this->action) AND $action !== $this->action)
        {
            // This rule has a specific action and it doesn't match the specific one passed
            return FALSE;
        }

        $resource_id = $resource->acl_id();

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

        // Now we know this rule matches the resource, check any match condition
        if ( ! empty($this->condition)
            and ! $resource->acl_conditions($user, $this->condition))
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
     * @param Validation $validation
     * @return $this
     */
	public function create(Validation $validation = NULL)
	{
		// Delete all more specific rules for this role
        $delete = DB::delete($this->_table_name);
        if (isset($this->_changed['role']))
        {
            $delete->where('role_id', '=', $this->_changed['role']);
        }
        else
        {
            $delete->where('role_id', 'IS', NULL);
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
		$delete->execute();

		// Create new rule
		return parent::create($validation);
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

} // End Model_AACL_Core_Rule