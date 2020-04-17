<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Resource;

/**
 * Defines an entity that is associated with a tenant ID.
 */
interface TenantOwnershipInterface
{
    /**
     * Get the ID of the Tenant that owns this resource for security purposes.
     * 
     * @return integer
     */
    public function getTenantId();
}
