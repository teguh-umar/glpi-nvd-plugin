<?php

class PluginNvdDatabaseutils {

    /**
     * Native GLPI entity restriction for a core table, ready to be merged into
     * a $DB->request() 'WHERE'.
     *
     * Wraps core's getEntitiesRestrictCriteria() (src/DbUtils.php) rather than
     * filtering by hand, so the plugin honours exactly what the rest of GLPI
     * honours: the active entity / sub-entity selection, "show all entities",
     * and is_recursive on tables that carry it.
     *
     * Two deliberate behaviours:
     *  - Tables with no `entities_id` column (global dropdowns such as
     *    glpi_manufacturers or glpi_operatingsystems) get no restriction.
     *  - In a cron / CLI context there is no active entity, and core's fallback
     *    is the root entity - which would silently hide every sub-entity asset
     *    from CVE correlation. Vulnerability matching must cover the whole
     *    instance, so no restriction is applied there either. Entity scoping is
     *    a *display* concern in this plugin, never a correlation one.
     *
     * @since 2.6.0
     *
     * @param string $table  Core table name (e.g. 'glpi_computers')
     *
     * @return array  Criteria to array_merge() into a WHERE (empty = no restriction)
     */
    public static function getEntityRestrictCriteria($table) {

        global $DB;

        if (!is_string($table) || $table === '') { return []; }

        if (!$DB->tableExists($table) || !$DB->fieldExists($table, 'entities_id')) { return []; }

        if (isCommandLine() || Session::isCron()) { return []; }

        // Same test core's maybeRecursive() makes, without needing the table to
        // resolve back to an itemtype.
        $is_recursive = $DB->fieldExists($table, 'is_recursive');

        return getEntitiesRestrictCriteria($table, '', '', $is_recursive);
    }

    /**
     * Whether the current session sees every entity ("show all entities" /
     * root profile with recursive access). Used to decide whether an
     * instance-wide diagnostic row may be shown.
     *
     * @since 2.6.0
     *
     * @return bool
     */
    public static function seesAllEntities() {

        if (isCommandLine() || Session::isCron()) { return true; }

        return !empty($_SESSION['glpishowallentities']);
    }

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
     * Every glpi_states dropdown entry (Setup > Dropdowns > Status), as
     * id => name. Used to populate the "Asset states in scope" multi-select
     * on the NVD Plugin config tab.
     *
     * @since 2.5.0
     *
     * @return array<int,string>
     */
    public static function getAllStates() {

        global $DB;

        $res = $DB->request(['SELECT' => ['id', 'name'], 'FROM' => 'glpi_states', 'ORDER' => 'name']);

        $states = [];
        foreach ($res as $row) {
            $states[(int) $row['id']] = $row['name'];
        }

        return $states;
    }

    /**
     * The glpi_states IDs an asset must currently have to be included in CVE
     * correlation, as configured on the NVD Plugin config tab. An empty
     * array means "no filter" (every state in scope - the default, and the
     * behaviour of every version before 2.5.0).
     *
     * @since 2.5.0
     *
     * @return int[]
     */
    public static function getScopedStateIDs() {

        global $DB;

        if (!$DB->fieldExists('glpi_plugin_nvd_config', 'scoped_states')) {
            return [];
        }

        $res = $DB->request(['SELECT' => 'scoped_states', 'FROM' => 'glpi_plugin_nvd_config']);

        if ($res->numrows() == 0) { return []; }

        $raw = $res->current()['scoped_states'];

        if (empty($raw)) { return []; }

        return array_values(array_filter(array_map('intval', explode(',', $raw))));
    }

    /**
     * Who can see the NVD Vulnerabilities tab: 'config_only' (default - same
     * gate as the CPE Association and NVD Plugin config tabs, i.e. GLPI
     * config/Setup right) or 'asset_read' (anyone with READ on Computer,
     * Phone or Software can see it on items they can otherwise view).
     * Configured on the NVD Plugin config tab.
     *
     * @since 2.5.0
     *
     * @return string
     */
    public static function getVulnTabVisibility() {

        global $DB;

        if (!$DB->fieldExists('glpi_plugin_nvd_config', 'vuln_tab_visibility')) {
            return 'config_only';
        }

        $res = $DB->request(['SELECT' => 'vuln_tab_visibility', 'FROM' => 'glpi_plugin_nvd_config']);

        if ($res->numrows() == 0) { return 'config_only'; }

        $value = $res->current()['vuln_tab_visibility'];

        return ($value === 'asset_read') ? 'asset_read' : 'config_only';
    }

    /**
     * IDs of the given itemtype's items that should be excluded from CVE
     * correlation: soft-deleted (is_deleted = 1), OR - when the admin has
     * configured a states scope on the NVD Plugin config tab - not currently
     * in one of those states. An empty scope means no state-based exclusion.
     *
     * @since 2.5.0
     *
     * @param string $itemtype
     *
     * @return int[]
     */
    public static function getOutOfScopeItemIDs($itemtype) {

        global $DB;

        $excluded = self::getDeletedItemIDs($itemtype);

        $scoped_states = self::getScopedStateIDs();

        if (empty($scoped_states)) {
            return $excluded;
        }

        if (!is_string($itemtype) || !class_exists($itemtype) || !is_subclass_of($itemtype, CommonDBTM::class)) {
            return $excluded;
        }

        $table = $itemtype::getTable();

        if (!$DB->fieldExists($table, 'states_id')) {
            return $excluded;
        }

        $res = $DB->request(['SELECT' => 'id', 'FROM' => $table, 'WHERE' => ['NOT' => ['states_id' => $scoped_states]]]);

        return array_values(array_unique(array_merge($excluded, array_map('intval', self::pushResToArray($res, 'id')))));
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