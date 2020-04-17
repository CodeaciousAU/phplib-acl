<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Principal;

/**
 * Defines a security principal (an identity that can be granted access to a resource)
 */
interface SecurityPrincipalInterface
{
    /**
     * @param string $permission One of the \Codeacious\Acl\Acl::PERMISSION_ constants
     * @param \Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @return boolean
     */
    public function hasPermission($permission, $resource=null);
}
