<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl;

use Codeacious\Acl\Exception\RuntimeException;
use Codeacious\Acl\Resource\ChildResourceInterface;
use Codeacious\Acl\Role\AbstractRole;
use Codeacious\Acl\Role\QualifiedRole;

/**
 * An instance of the application's access control list, which defines all access rules.
 */
class Acl extends \Laminas\Permissions\Acl\Acl
{
    /**
     * @var array Mapping to role code to custom class name
     */
    private $roleClassMap = [];


    /**
     * Constructor.
     */
    public function __construct()
    {
    }

    /**
     * @param string $roleCode
     * @param string $className A fully qualified class name
     * @return Acl This
     */
    public function addRoleClassMapping($roleCode, $className)
    {
        $this->roleClassMap[$roleCode] = $className;
        return $this;
    }

    /**
     * @param string $roleCode
     * @return string
     */
    public function getRoleClass($roleCode)
    {
        if (!empty($this->roleClassMap[$roleCode]))
        {
            $className = $this->roleClassMap[$roleCode];
            if (!class_exists($className))
            {
                throw new RuntimeException('Custom global role class '.$className.' does not '
                    .'exist');
            }
            return $className;
        }
        return '\Codeacious\Acl\Role\QualifiedRole';
    }

    /**
     * Retrieve the named role, creating it and adding it to the ACL if necessary.
     *
     * @param string $roleCode
     * @return \Codeacious\Acl\Role\AbstractRole|null
     */
    public function getRole($roleCode)
    {
        if ($this->hasRole($roleCode))
            return parent::getRole($roleCode);

        $className = $this->getRoleClass($roleCode);
        $role = new $className($roleCode);
        if (!$role instanceof AbstractRole)
        {
            throw new RuntimeException('Role class '.$className.' does not extend '
                .'\Codeacious\Acl\Role\AbstractRole');
        }

        /* @var $role \Codeacious\Acl\Role\AbstractRole */
        $this->addRole($role, $role->getParentRoles($this));
        $role->configureRules($this);

        return $role;
    }

    /**
     * @param string $fqn
     * @return \Codeacious\Acl\Role\AbstractRole|null
     */
    public function getRoleByFqn($fqn)
    {
        //Separate the qualifiers suffix
        $matches = null;
        if (preg_match('/^(.+)\[(.*)\]$/', $fqn, $matches))
        {
            $roleCode = $matches[1];
            $qualifiersStr = $matches[2];
        }
        else
        {
            $roleCode = $fqn;
            $qualifiersStr = '';
        }

        //Convert the qualifiers to an array
        $qualifiers = [];
        foreach (explode(',', $qualifiersStr) as $str)
        {
            if (strpos($str, '=') === false)
                continue;
            list($name, $value) = explode('=', $str, 2);
            $qualifiers[$name] = $value;
        }

        if (empty($qualifiers))
            return $this->getRole($roleCode);
        else
            return $this->getQualifiedRole($roleCode, $qualifiers);
    }
    
    /**
     * Retrieve an instance of the given role type with the specified qualifiers, creating it and
     * adding it to the ACL if necessary.
     * 
     * @param string $type
     * @param array $qualifiers
     * @return \Codeacious\Acl\Role\QualifiedRole|null
     */
    public function getQualifiedRole($type, array $qualifiers=[])
    {
        $roleId = QualifiedRole::formatRoleId($type, $qualifiers);
        if ($this->hasRole($roleId))
            return parent::getRole($roleId);

        $className = $this->getRoleClass($type);
        $role = new $className($type, $qualifiers);
        if (!$role instanceof QualifiedRole)
        {
            throw new RuntimeException('Role class '.$className.' does not extend '
                .'\Codeacious\Acl\Role\QualifiedRole');
        }

         /* @var $role \Codeacious\Acl\Role\QualifiedRole */
        $this->addRole($role, $role->getParentRoles($this));
        $role->configureRules($this);
        
        return $role;
    }
    
    /**
     * {@see \Laminas\Permissions\Acl\Acl::addResource()}
     * 
     * @param \Laminas\Permissions\Acl\Resource\ResourceInterface|string $resource
     * @param \Laminas\Permissions\Acl\Resource\ResourceInterface|string $parent
     * @return $this
     */
    public function addResource($resource, $parent = null)
    {
        if (empty($parent) && is_object($resource) && $resource instanceof ChildResourceInterface)
            return parent::addResource($resource, $resource->getParentResource());
        
        return parent::addResource($resource, $parent);
    }


    const PERMISSION_QUERY = 'query';
    const PERMISSION_CREATE = 'create';
    const PERMISSION_READ = 'read';
    const PERMISSION_UPDATE = 'update';
    const PERMISSION_DELETE = 'delete';
}
