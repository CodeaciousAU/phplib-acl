<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Assertion;

use Codeacious\Acl\Resource\TenantOwnershipInterface;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Permissions\Acl\Resource\ResourceInterface;
use Laminas\Permissions\Acl\Role\RoleInterface;

/**
 * Security assertion that returns true when the tenant ID of the resource being tested matches the
 * tenant ID of this object.
 */
class TenantOwnershipAssertion implements AssertionInterface
{
    /**
     * @var integer
     */
    protected $tenantId;
    
    
    /**
     * @param integer $tenantId
     */
    public function __construct($tenantId)
    {
        $this->tenantId = $tenantId;
    }
    
    /**
     * {@see \Laminas\Permissions\Acl\Assertion\AssertionInterface::assert()}
     *
     * @param \Laminas\Permissions\Acl\Acl $acl
     * @param \Laminas\Permissions\Acl\Role\RoleInterface $role
     * @param \Laminas\Permissions\Acl\Resource\ResourceInterface $resource
     * @param string $privilege
     * @return bool
     */
    public function assert(Acl $acl, RoleInterface $role = null, ResourceInterface $resource = null,
        $privilege = null)
    {
        if (is_object($resource)
            && $resource instanceof TenantOwnershipInterface
            && $resource->getTenantId() == $this->tenantId)
        {
            return true;
        }
        
        return false;
    }
}
