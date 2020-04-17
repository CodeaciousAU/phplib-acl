<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Acl\Role;

/**
 * A security role consisting of a generic role type plus qualifiers that are specified when the
 * role is granted.
 */
class QualifiedRole extends AbstractRole
{
    /**
     * @var string
     */
    protected $type;

    /**
     * @var array
     */
    protected $qualifiers;


    /**
     * @param string $type
     * @param array $qualifiers Associative array of strings
     */
    public function __construct($type, array $qualifiers=[])
    {
        $this->type = $type;
        $this->qualifiers = $qualifiers;
        parent::__construct(self::formatRoleId($type, $qualifiers));
    }

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @return array
     */
    public function getQualifiers()
    {
        return $this->qualifiers;
    }

    /**
     * @param string $name
     * @return string|null
     */
    public function getQualifier($name)
    {
        if (!isset($this->qualifiers[$name]))
            return null;
        return $this->qualifiers[$name];
    }

    /**
     * Returns true if the role has all the named qualifiers and no others.
     *
     * @param array $expectedQualifierNames
     * @return boolean
     */
    protected function hasExpectedQualifiers(array $expectedQualifierNames)
    {
        if (count($this->qualifiers) != count($expectedQualifierNames))
            return false;

        foreach ($expectedQualifierNames as $name)
        {
            if (!isset($this->qualifiers[$name]))
                return false;
        }

        return true;
    }

    /**
     * @param string $type
     * @param array $qualifiers Associative array of strings
     * @return string
     */
    public static function formatRoleId($type, array $qualifiers=[])
    {
        //Sort qualifier keys alphabetically, to ensure that a consistent string will be produced
        //every time that set of qualifiers is specified.
        $keys = array_keys($qualifiers);
        sort($keys, SORT_STRING);

        $parts = [];
        foreach ($keys as $key)
            $parts[] = $key.'='.$qualifiers[$key];

        $qualifierStr = implode(',', $parts);

        $fqn = $type;
        if (!empty($qualifierStr))
            $fqn .= '['.$qualifierStr.']';
        return $fqn;
    }
}
