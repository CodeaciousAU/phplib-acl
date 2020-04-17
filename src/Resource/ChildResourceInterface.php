<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Resource;

/**
 * Defines a resource which has a parent resource.
 */
interface ChildResourceInterface extends \Laminas\Permissions\Acl\Resource\ResourceInterface
{
    /**
     * Get the parent resource of this resource.
     * 
     * @return \Laminas\Permissions\Acl\Resource\ResourceInterface|string
     */
    public function getParentResource();
}
