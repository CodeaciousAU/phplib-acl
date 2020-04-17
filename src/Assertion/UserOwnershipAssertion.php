<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Assertion;

use Codeacious\Acl\Resource\UserOwnershipInterface;
use Laminas\Permissions\Acl\Acl;
use Laminas\Permissions\Acl\Assertion\AssertionInterface;
use Laminas\Permissions\Acl\Resource\ResourceInterface;
use Laminas\Permissions\Acl\Role\RoleInterface;

/**
 * Security assertion that returns true when the user ID of the resource being tested matches the
 * user ID of this object.
 */
class UserOwnershipAssertion implements AssertionInterface
{
    /**
     * @var integer
     */
    protected $userId;


    /**
     * @param integer $userId
     */
    public function __construct($userId)
    {
        $this->userId = $userId;
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
            && $resource instanceof UserOwnershipInterface
            && $resource->getUserId() == $this->userId)
        {
            return true;
        }

        return false;
    }
}
