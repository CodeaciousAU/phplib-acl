<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Role;

use Codeacious\Acl\Acl;
use Laminas\Permissions\Acl\Role\GenericRole;

/**
 * Base class for all security roles.
 */
abstract class AbstractRole extends GenericRole
{
    /**
     * @param \Codeacious\Acl\Acl $acl
     * @return \Laminas\Permissions\Acl\Role\RoleInterface[]
     */
    public function getParentRoles(Acl $acl)
    {
        return array();
    }
    
    /**
     * @param \Codeacious\Acl\Acl $acl
     * @return void
     */
    public function configureRules(Acl $acl)
    {
    }
}
