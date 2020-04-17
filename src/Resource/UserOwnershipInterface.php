<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Resource;

/**
 * Defines an entity that is associated with a user ID.
 */
interface UserOwnershipInterface
{
    /**
     * Get the ID of the User that owns this resource for security purposes.
     * 
     * @return integer
     */
    public function getUserId();
}
