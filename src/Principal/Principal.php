<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Principal;

use Codeacious\Acl\Acl;
use Codeacious\Acl\Exception\InvalidArgumentException;
use Codeacious\Acl\Exception\InvalidStateException;
use Laminas\Permissions\Acl\Role\RoleInterface;

/**
 * A basic security principal (which also functions as an ACL role).
 */
class Principal implements SecurityPrincipalInterface, RoleInterface
{
    /**
     * @var string
     */
    protected $roleId;
    
    /**
     * @var string[] Array of role IDs
     */
    protected $parentRoles;
    
    /**
     * @var \Codeacious\Acl\Acl
     */
    protected $acl;
    
    
    /**
     * @param string $roleId A unique identifier for this principal's security role
     */
    public function __construct($roleId)
    {
        $this->roleId = $roleId;
        $this->parentRoles = array();
    }

    /**
     * {@see \Laminas\Permissions\Acl\Role\RoleInterface::getRoleId()}
     * 
     * @return string
     */
    public function getRoleId()
    {
        return $this->roleId;
    }
    
    /**
     * Add a role that this principal will inherit permissions from.
     * 
     * @param string|\Laminas\Permissions\Acl\Role\RoleInterface $role
     * @return Principal This
     */
    public function grantRole($role)
    {
        if (is_object($role) && $role instanceof RoleInterface)
            $role = $role->getRoleId();
        else if (!is_string($role))
        {
            throw new InvalidArgumentException(__METHOD__.'() expects a string or an instance of '
                .'\Zend\Permissions\Acl\Role\RoleInterface');
        }
        
        $this->parentRoles[] = $role;
        return $this;
    }
    
    /**
     * Remove a role that this principal is inheriting permissions from.
     * 
     * @param string|\Laminas\Permissions\Acl\Role\RoleInterface $role
     * @return Principal This
     */
    public function revokeRole($role)
    {
        if (is_object($role) && $role instanceof RoleInterface)
            $role = $role->getRoleId();
        else if (!is_string($role))
        {
            throw new InvalidArgumentException(__METHOD__.'() expects a string or an instance of '
                .'\Zend\Permissions\Acl\Role\RoleInterface');
        }
        
        $idx = array_search($role, $this->parentRoles);
        if ($idx !== false)
            unset($this->parentRoles[$idx]);
        
        return $this;
    }
    
    /**
     * @param string|\Laminas\Permissions\Acl\Role\RoleInterface $role
     * @return boolean
     */
    public function hasRole($role)
    {
        if (is_object($role) && $role instanceof RoleInterface)
            $role = $role->getRoleId();
        else if (!is_string($role))
        {
            throw new InvalidArgumentException(__METHOD__.'() expects a string or an instance of '
                .'\Zend\Permissions\Acl\Role\RoleInterface');
        }
        
        return (array_search($role, $this->parentRoles) !== false);
    }
    
    /**
     * Apply any changes to this principal's list of roles.
     * 
     * This is only necessary if you have called grantRole() or revokeRole() after addToAcl().
     * 
     * @return Principal This
     */
    public function flushRoles()
    {
        if ($this->acl)
        {
            $acl = $this->acl;
            $this->removeFromAcl()
                 ->addToAcl($acl);
        }
        return $this;
    }
    
    /**
     * @param \Codeacious\Acl\Acl $acl
     * @return Principal This
     */
    public function addToAcl(Acl $acl)
    {
        $this->acl = $acl;
        $this->acl->addRole($this, $this->parentRoles);
        $this->configureRules($acl);
        return $this;
    }
    
    /**
     * @return Principal This
     */
    public function removeFromAcl()
    {
        if ($this->acl)
        {
            $this->acl->removeRole($this);
            $this->acl = null;
        }
        return $this;
    }

    /**
     * @param \Codeacious\Acl\Acl $acl
     * @return void
     */
    public function configureRules(Acl $acl)
    {
        //An opportunity for subclasses to add custom ACL rules in addition to those inherited
        //from this principal's roles.
    }

    /**
     * {@see \Codeacious\Acl\Principal\SecurityPrincipalInterface}
     * 
     * @param string $permission One of the \Codeacious\Acl\Acl::PERMISSION_ constants
     * @param \Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @return boolean
     * 
     * @throws \Codeacious\Acl\Exception\InvalidStateException
     */
    public function hasPermission($permission, $resource = null)
    {
        if (!$this->acl)
        {
            throw new InvalidStateException('Unable to determine permissions for this security'
                 .'principal because it has not been added to an ACL');
        }
        
        if ($resource && !$this->acl->hasResource($resource))
            $this->acl->addResource($resource);
        
        return $this->acl->isAllowed($this, $resource, $permission);
    }
}
