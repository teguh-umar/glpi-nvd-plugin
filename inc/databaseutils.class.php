<?php

class PluginNvdDatabaseutils {

    /**
     * IDs of the given itemtype's items currently in the GLPI trash
     * (is_deleted = 1). Used to exclude soft-deleted assets from vulnerability
     * matching, counts and display - a deleted asset is not part of the live
     * inventory any more even though its installation rows are kept until it
     * is purged.
     *
     * @since 2.5.0
     *
     * @param string $itemtype
     *
     * @return int[]
     */
    public static function getDeletedItemIDs($itemtype) {

        global $DB;

        if (!is_string($itemtype) || !class_exists($itemtype) || !is_subclass_of($itemtype, CommonDBTM::class)) {
            return [];
        }

        $table = $itemtype::getTable();

        if (!$DB->fieldExists($table, 'is_deleted')) {
            return [];
        }

        $res = $DB->request(['SELECT' => 'id', 'FROM' => $table, 'WHERE' => ['is_deleted' => 1]]);

        return array_map('intval', self::pushResToArray($res, 'id'));
    }

    /**
     * Every manufacturer name known to this GLPI instance (Setup > Dropdowns >
     * Manufacturers). Used as a local, always-available fallback source for the
     * CPE Association tab's vendor list when the external CIRCL directory
     * (cve.circl.lu) cannot be reached.
     *
     * @since 2.4.5
     *
     * @return string[]
     */
    public static function getManufacturerNames() {

        global $DB;

        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_manufacturers',
                             'ORDER' => 'name']);

        return array_values(array_filter(self::pushResToArray($res, 'name')));
    }

    /**
     * Queries the GLPI database and returns the default language from settings
     * 
     * @since 1.0.0
     * 
     * @return string    GLPI default language
     */
    public static function getGLPILanguage() {

        global $DB;

        /***********************************************************************************************
         * Request GLPI default language from settings
         * 
         *  SELECT value
         *  FROM glpi_configs
         *  WHERE name = language
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'value',
                             'FROM' => 'glpi_configs',
                             'WHERE' => ['name' => 'language']]);

        if ($res->numrows() != 0) {

            $row = $res->current();

            return $row['value'];
        }

        return null;
    }

    /**
     * Combine values from database query result into an array
     * 
     * @since 1.0.0
     * 
     * @param DBmysqlIterator   $res        Array containing database queried rows
     * @param string            $value      Value to append to array of results
     * @param string            $key        Optional key for which to append the value
     * 
     * @return array    Array values
     */
    public static function pushResToArray($res, $value, $key=NULL) {

        $array = [];

        if ($key == NULL) {

            foreach ($res as $id => $row) {
                $array[] = $row[$value];
            }

        } else {

            foreach ($res as $id => $row) {
                $array[$row[$key]] = $row[$value];
            }
        }

        return $array;
    }

    /**
     * Queries the GLPI database and returns the API key set for the NVD API
     * 
     * @since 1.0.0
     * 
     * @return string    NVD API key
     */
    public static function getNvdApiKey() {

        global $DB;

        /***********************************************************************************************
         * Request api key from glpi configuration
         * 
         *  SELECT api_key
         *  FROM glpi_plugin_nvd_config 
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'api_key',
                             'FROM' => 'glpi_plugin_nvd_config']);

        if ($res->numrows() != 0) {

            $row = $res->current();

            return $row['api_key'];
        }

        return NULL;
    }

    /*
     * getNextId() was removed in 2.4.1: it hardcoded TABLE_SCHEMA = 'glpi' to
     * read INFORMATION_SCHEMA.TABLES.AUTO_INCREMENT, which returns nothing (and
     * is stale even when it matches) on any instance whose database isn't
     * literally named "glpi" - the resulting null/wrong value made
     * PluginNvdUpdatevuln attach new CVE descriptions/configurations/version
     * links to the wrong vuln_id (or none). Callers now use
     * DBmysql::insertId() right after the insert instead of tracking a
     * separate counter.
     */

    /**
     * Transform OS related info IDs to actual values
     * 
     * @since 1.0.0
     * 
     * @param array $row Array containing OS name, version, kernel version and service pack IDs on the GLPI database
     * 
     * @return array     Array containing OS name, version, kernel, kernel version and service pack
     */
    public static function requestOSdata($row) {

        global $DB;

        $OS_ID                  = $row['operatingsystems_id'];
        $OS_version_ID          = $row['operatingsystemversions_id'];
        $OS_kernel_version_ID   = $row['operatingsystemkernelversions_id'];
        $OS_service_pack_ID     = $row['operatingsystemservicepacks_id'];

        /***********************************************************************************************
         * Request operating system name
         * 
         *  SELECT name
         *  FROM glpi_operatingsystems
         *  WHERE id = $OS_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystems',
                             'WHERE' => ['id' => $OS_ID]]);

        $name = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system version
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemversions
         *  WHERE id = $OS_version_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemversions',
                             'WHERE' => ['id' => $OS_version_ID]]);

        $version = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system version
         * 
         *  SELECT name, glpi_operatingsystemkernelversions
         *  FROM glpi_operatingsystemkernelversions
         *  WHERE id = $OS_kernel_version_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['name', 'operatingsystemkernels_id'],
                             'FROM' => 'glpi_operatingsystemkernelversions',
                             'WHERE' => ['id' => $OS_kernel_version_ID]]);

        $kernelVersion  = ($res->numrows() == 1) ? ($res->current())['name'] : null;
        $OS_kernel_ID   = ($res->numrows() == 1) ? ($res->current())['operatingsystemkernels_id'] : 0;

        /***********************************************************************************************
         * Request operating system kernel
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemkernels
         *  WHERE id = $OS_kernel_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemkernels',
                             'WHERE' => ['id' => $OS_kernel_ID]]);

        $kernel = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        /***********************************************************************************************
         * Request operating system service pack
         * 
         *  SELECT name
         *  FROM glpi_operatingsystemservicepacks
         *  WHERE id = $OS_service_pack_ID
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'name',
                             'FROM' => 'glpi_operatingsystemservicepacks',
                             'WHERE' => ['id' => $OS_service_pack_ID]]);

        $servicePack = ($res->numrows() == 1) ? ($res->current())['name'] : null;

        return [$name, $version, $kernel, $kernelVersion, $servicePack];
    }
}

?>