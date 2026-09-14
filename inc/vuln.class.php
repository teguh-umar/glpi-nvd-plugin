<?php

class PluginNvdVuln extends CommonDBTM {

    /**
     * Check if can view item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    static function canView(): bool {

        if (Config::canView()) { return true; }

        // Configurable on the NVD Plugin config tab: 'asset_read' opens the
        // Vulnerabilities tab to anyone who can already view the underlying
        // Computer/Phone/Software (the CPE Association and config tabs stay
        // Config::canView()-only regardless of this setting).
        if (PluginNvdDatabaseutils::getVulnTabVisibility() === 'asset_read') {
            return Session::haveRight('computer', READ)
                || Session::haveRight('phone', READ)
                || Session::haveRight('software', READ);
        }

        return false;
    }

    /**
     * Whether the given item should be excluded from vulnerability tracking:
     * soft-deleted (trashed), or - when an admin-configured asset-states
     * scope is set on the NVD Plugin config tab - not currently in one of
     * those states.
     *
     * @since 2.5.0
     *
     * @param CommonGLPI $item
     *
     * @return bool
     */
    private static function isOutOfScope(CommonGLPI $item) {

        if (method_exists($item, 'isDeleted') && $item->isDeleted()) {
            return true;
        }

        $scoped_states = PluginNvdDatabaseutils::getScopedStateIDs();

        if (!empty($scoped_states) && isset($item->fields['states_id'])) {
            return !in_array((int) $item->fields['states_id'], $scoped_states, true);
        }

        return false;
    }

    /**
     * Get tab name for displayed item
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item
     * @param int        $withtemplate
     *
     * @return boolean
     */
    function getTabNameForItem(CommonGLPI $item, $withtemplate=0) {

        // A trashed or out-of-scope asset isn't live inventory - don't show a
        // (potentially stale, soon-to-be-pruned) vulnerability count for it.
        if (self::isOutOfScope($item)) {
            return self::createTabEntry(__('Vulnerabilities'), 0);
        }

        $totalVulnerabilities = 0;

        switch($item::getType()) {

            case Software::getType():

                $totalVulnerabilities = self::countForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDevice($item);
                break;

            default:

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDashboard();
        }
        
        return self::createTabEntry(__('Vulnerabilities'), $totalVulnerabilities);
    }

    /**
     * Count number of vulnerabilities related to a given software
     *
     * @since 1.0.0
     *
     * @param Software $item        Software item to look vulnerabilities for
     *
     * @return int                  Number of vulnerabilities found
     */
    private static function countForSoftware(Software $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);

        return $res->numrows();
    }

    /**
     * Count number of vulnerabilities related to a given device
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item      Device item to look vulnerabilities for
     *
     * @return array                Array containing the number of found vulnerabilities and the division between software and system vulnerabilities
     */
    private static function countForDevice(CommonGLPI $item) {

        global $DB;

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                                         'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                                     'glpi_items_softwareversions' => 'softwareversions_id']]],
                                         'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                                         'GROUPBY' => 'vuln_id']);

        $NsoftwareVulns = $res->numrows();

        $softwareVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        /***********************************************************************************************
         * Request operating system version for the given device
         * 
         *  SELECT operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id,
         *      operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                             'FROM' => 'glpi_items_operatingsystems',
                             'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()]]);

        if ($res->numrows() == 0) { return [$NsoftwareVulns, $NsoftwareVulns, 0]; }

        [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($res->current());

        $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

        if (is_null($installationData)) { return [$NsoftwareVulns, $NsoftwareVulns, 0]; }

        $configuration = $installationData['configuration'];

        /***********************************************************************************************
         * Request every operating system vulnerability associated with the given device
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  WHERE system_configuration = $configuration
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                                         'WHERE' => ['system_configuration' => $configuration]]);

        $NsystemVulns = $res->numrows();

        $systemVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        $totalVulns = count(array_unique(array_merge($softwareVulns, $systemVulns)));

        return [$totalVulns, $NsoftwareVulns, $NsystemVulns];
    }

    /**
     * Count total number of vulnerabilities
     *
     * @since 1.0.0
     *
     * @return array Array containing the number of found vulnerabilities and the division between software and system vulnerabilities
     */
    private static function countForDashboard() {

        global $DB;

        /***********************************************************************************************
         * Request every software vulnerability registered
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_software_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                                         'GROUPBY' => 'vuln_id']);

        $NsoftwareVulns = $res->numrows();
        
        $softwareVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        /***********************************************************************************************
         * Request every operating system vulnerability registered
         * 
         *  SELECT vuln_id 
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => 'vuln_id',
                                         'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                                         'GROUPBY' => 'vuln_id']);

        $NsystemVulns = $res->numrows();

        $systemVulns = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');

        $totalVulns = count(array_unique(array_merge($softwareVulns, $systemVulns)));

        return [$totalVulns, $NsoftwareVulns, $NsystemVulns];
    }

    /**
     * Display tab content for given item
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item       Item for which to display vulnerabilities
     * @param int $tabnum
     * @param int $withtemplate
     *
     * @return boolean
     */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        // A trashed or out-of-scope asset isn't live inventory - vulnerability
        // tracking is suspended for it.
        if (self::isOutOfScope($item)) {
            $message = (method_exists($item, 'isDeleted') && $item->isDeleted())
                ? __s('This item is in the trash. Vulnerability tracking is suspended until it is restored.')
                : __s('This item\'s current state is outside the asset states configured for vulnerability tracking (NVD Plugin config tab).');
            echo '<div class="alert alert-secondary m-2">' . $message . '</div>';
            return true;
        }

        switch($item::getType()) {

            case Software::getType():

                self::displayForSoftware($item);
                break;

            case Computer::getType():
            case Phone::getType():

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDevice($item);
                self::displayForDevice($item, $NsoftwareVulns, $NsystemVulns);
                break;

            default:

                [$totalVulnerabilities, $NsoftwareVulns, $NsystemVulns] = self::countForDashboard();
                self::displayForDashboard($NsoftwareVulns, $NsystemVulns);
        }
        
        return true;
    }

    /**
     * Display tab content for given Software item
     *
     * @since 1.0.0
     *
     * @param Software $item       Software item for which to display vulnerabilities
     *
     * @return void
     */
    private static function displayForSoftware(Software $item) {

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request vulnerabilities to which the given software's different versions are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *   GROUP_CONCAT(glpi_softwareversions.id, ':', glpi_softwareversions.name) AS version
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = glpi_softwareversions.id
         *  WHERE softwares_id = $item->getID()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                                'vuln_id AS VULN_ID',
                                new QueryExpression("GROUP_CONCAT(`glpi_softwareversions`.`id`, ':', `glpi_softwareversions`.`name`) AS `version`")
                             ],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                             'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                                     'glpi_softwareversions' => 'id']]] ,
                             'WHERE' => ['softwares_id' => $item->getID()],
                             'GROUPBY' => 'vuln_id']);
        
        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $versions = explode(',', $row['version']);

            $instances = [];

            foreach ($versions as $version) {

                [$id, $name] = explode(':', $version);

                $instances[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/softwareversion.form.php?id=" . (int)$id . '">' . htmlescape($name) . '</a>';
            }

            $vulnerabilities[$row['VULN_ID']] = implode(', ', $instances);
        }

        /***********************************************************************************************
         * Request CPE vendor and product name associated with given software
         * 
         *  SELECT vendor_name, product_name
         *  FROM glpi_plugin_nvd_cpe_software_associations 
         *  WHERE softwares_id = $item->getID()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['vendor_name', 'product_name'],
                                'FROM' => 'glpi_plugin_nvd_cpe_software_associations',
                                'WHERE' => ['softwares_id' => $item->getID()]]);

        if ($res->numrows() == 0) { return; }

        $row = $res->current();
        $filters = array(
            'vendor_name' => $row['vendor_name'], 
            'product_name' => $row['product_name']
        );

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of vulnerabilities associated with given software
        echo self::displayVulnerabilityList($res, $vulnerabilities, __('Versions'), $filters);
    }

    /**
     * Display tab content for given Device item
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item      Device item for which to display vulnerabilities
     * @param int $NsoftwareVulns   Number of software vulnerabilities
     * @param int $NsystemVulns     Number of operating system vulnerabilities
     *
     * @return void
     */
    private static function displayForDevice(CommonGLPI $item, $NsoftwareVulns, $NsystemVulns) {

        global $DB, $CFG_GLPI;

        /***************************\
        |* Software Vulnerabilities |
        \***************************/

        /***********************************************************************************************
         * Request vulnerabilities to which the given device's different programs are vulnerable
         * 
         *  SELECT vuln_id AS VULN_ID, 
         *         GROUP_CONCAT(glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id) AS version
         *  FROM glpi_plugin_nvd_vulnerable_software_versions 
         *  INNER JOIN glpi_items_softwareversions 
         *  ON glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id = 
         *     glpi_items_softwareversions.softwareversions_id
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(`glpi_plugin_nvd_vulnerable_software_versions`.`softwareversions_id`) AS `version`")
                ],
                'FROM' => 'glpi_plugin_nvd_vulnerable_software_versions',
                'INNER JOIN' => ['glpi_items_softwareversions' => ['FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                                                                              'glpi_items_softwareversions' => 'softwareversions_id']]],
                'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            /***********************************************************************************************
             * Request IDs and names from programs that are vulnerable to the obtained vulnerabilities
             * 
             *  SELECT DISTINCT glpi_softwares.id, glpi_softwares.name
             *  FROM glpi_softwares 
             *  INNER JOIN glpi_softwareversions 
             *  ON glpi_softwares.id = glpi_softwareversions.softwares_id
             *  WHERE glpi_softwareversions.id IN explode(',', $row['version'])
             **********************************************************************************************/
            $res_2 = $DB->request(['SELECT' => ['glpi_softwares.id', 'glpi_softwares.name'],
                                 'DISTINCT' => true,
                                 'FROM' => 'glpi_softwares',
                                 'INNER JOIN' => ['glpi_softwareversions' => ['FKEY' => ['glpi_softwares' => 'id',
                                                                                         'glpi_softwareversions' => 'softwares_id']]],
                                 'WHERE' => ['glpi_softwareversions.id' => explode(',', $row['version'])]]);

            $programs = [];

            //Transform names and IDs to liks to vulnerable programs in GLPI
            foreach ($res_2 as $id_2 => $row_2) {
                $programs[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/software.form.php?id=" . (int)$row_2['id'] . '">' . htmlescape($row_2['name']) . '</a>';
            }
            
            $vulnerabilities[$row['VULN_ID']] = implode(',', $programs);
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        //Display list of software vulnerabilities associated with given device
        $softwareList = self::displayVulnerabilityList($res, $vulnerabilities, __('Programs'));

        /**********************************\
        |* Operating Sytem Vulnerabilities |
        \**********************************/

        $vulnerabilities = [];
        $filters = [];

        /***********************************************************************************************
         * Request operating system version for the given device
         * 
         *  SELECT operatingsystems_id, operatingsystemversions_id, operatingsystemkernelversions_id,
         *      operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         *  WHERE items_id' = $item->getID() AND 'itemtype' = $item->getType()
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['operatingsystems_id', 'operatingsystemversions_id', 'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                                          'FROM' => 'glpi_items_operatingsystems',
                                          'WHERE' => ['items_id' => $item->getID(), 'itemtype' => $item->getType()]]);

        if ($res->numrows() == 1) { 

            [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($res->current());

            $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

            if (!is_null($installationData)) {

                $filters = array(
                    'vendor_name' => $installationData[CPE_VENDOR], 
                    'product_name' => $installationData[CPE_PRODUCT]
                );

                $configuration = $installationData['configuration'];

                /***********************************************************************************************
                * Request every operating system vulnerability associated with the given device
                * 
                *  SELECT vuln_id 
                *  FROM glpi_plugin_nvd_vulnerable_system_versions
                *  WHERE system_configuration = $configuration
                **********************************************************************************************/
                $res = $DB->request(['SELECT' => 'vuln_id',
                'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                'WHERE' => ['system_configuration' => $configuration]]);

                $vulnerabilities = PluginNvdDatabaseutils::pushResToArray($res, 'vuln_id');
            }
        }

        //Request information on the obtained CVE records 
        $res = self::requestVulnerabilities($vulnerabilities);

        // Display list of OS vulnerabilities
        $systemList = self::displayVulnerabilityList($res, $vulnerabilities, NULL, $filters);;

        // Display both software and system vulnerabilities organized with nav tabs
        self::displayNavTabs($softwareList, $NsoftwareVulns, $systemList, $NsystemVulns);
    }

    /**
     * Display tab content on central dashboard
     *
     * @since 1.0.0
     * 
     * @param int $NsoftwareVulns   Number of software vulnerabilities
     * @param int $NsystemVulns     Number of operating system vulnerabilities
     *
     * @return void
     */
    private static function displayForDashboard($NsoftwareVulns, $NsystemVulns){

        $tally = [];

        $softwareList = self::gatherSoftwareVulnList($tally);
        $systemList   = self::gatherSystemVulnList($tally);

        // Display both software and system vulnerabilities organized with nav tabs
        self::displayNavTabs($softwareList, $NsoftwareVulns, $systemList, $NsystemVulns);
    }

    /**
     * Standalone page (Tools > NVD Vulnerabilities) listing every downloaded CVE
     * and the assets it affects, with a severity summary and client-side
     * search / severity filter / column sort.
     *
     * @since 2.1.0
     *
     * @return void
     */
    public static function showVulnerabilityPage() {

        $tally = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0, 'NONE' => 0];

        $softwareList = self::gatherSoftwareVulnList($tally, true);
        $systemList   = self::gatherSystemVulnList($tally, true);

        [$totalVulns, $NsoftwareVulns, $NsystemVulns] = self::countForDashboard();

        echo '<div class="nvd-vuln-page container-fluid mt-2">';

        echo <<<'CSS'
<style>
.nvd-vuln-page .nvd-kpi { text-align: center; }
.nvd-vuln-page .nvd-kpi-value { font-size: 1.9rem; font-weight: 700; line-height: 1.1; }
.nvd-vuln-page .nvd-kpi-label { font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; color: var(--bs-secondary-color, #6c757d); }
.nvd-vuln-page .nvd-kpi-btn { cursor: pointer; transition: box-shadow .12s, transform .12s; }
.nvd-vuln-page .nvd-kpi-btn:hover { box-shadow: 0 0 0 1px var(--bs-primary, #206bc4); }
.nvd-vuln-page .nvd-kpi-btn.active { box-shadow: 0 0 0 2px var(--bs-primary, #206bc4); transform: translateY(-1px); }
.nvd-vuln-page .nvd-kpi-value.text-yellow { color: #b8860b !important; }
.nvd-vuln-page .nav-tabs .badge { color: #fff !important; background-color: var(--bs-primary, #206bc4) !important; }
.nvd-vuln-page .vuln-table td, .nvd-vuln-page .vuln-table th { word-wrap: break-word; }
.nvd-vuln-page th.nvd-sortable { cursor: pointer; user-select: none; }
.nvd-vuln-page th.nvd-sortable::after { content: " \2195"; opacity: .35; }
.nvd-vuln-page th.nvd-sortable[data-sort-dir="asc"]::after { content: " \2191"; opacity: 1; }
.nvd-vuln-page th.nvd-sortable[data-sort-dir="desc"]::after { content: " \2193"; opacity: 1; }
</style>
CSS;

        echo self::renderSeveritySummary($tally, $totalVulns);

        if ($totalVulns == 0) {
            echo '<div class="card"><div class="card-body text-center text-muted py-4">'
               . '<i class="ti ti-shield-check" style="font-size:2rem"></i><br>'
               . __s('No vulnerabilities have been downloaded yet. Set the NVD API key in Setup > General > NVD Plugin, associate CPE names to your software, then run the "UpdateVulnTask" automatic action.')
               . '</div></div></div>';
            return;
        }

        self::displayNavTabs($softwareList, $NsoftwareVulns, $systemList, $NsystemVulns);

        echo '</div>';

        // js/nvd.js self-initialises on `.nvd-vuln-page`; this is only a fast
        // path for when the script is already evaluated.
        echo Html::scriptBlock('if (window.nvdVulnPageInit) { nvdVulnPageInit(); }');
    }

    /**
     * Render the Total / Critical / High / Medium / Low KPI tiles.
     *
     * @since 2.1.0
     *
     * @param array $tally         Map of severity label => count
     * @param int   $totalVulns    Total number of distinct vulnerabilities
     *
     * @return string
     */
    private static function renderSeveritySummary(array $tally, $totalVulns) {

        $tiles = [
            ['label' => __('Total'),    'value' => (int)$totalVulns,              'cls' => '',            'sev' => ''],
            ['label' => __('Critical'), 'value' => (int)($tally['CRITICAL'] ?? 0), 'cls' => 'text-red',    'sev' => 'CRITICAL'],
            ['label' => __('High'),     'value' => (int)($tally['HIGH'] ?? 0),     'cls' => 'text-orange', 'sev' => 'HIGH'],
            ['label' => __('Medium'),   'value' => (int)($tally['MEDIUM'] ?? 0),   'cls' => 'text-yellow', 'sev' => 'MEDIUM'],
            ['label' => __('Low'),      'value' => (int)($tally['LOW'] ?? 0),      'cls' => 'text-green',  'sev' => 'LOW'],
        ];

        $out = '<div class="row row-cards mb-3 nvd-kpi-row">';

        foreach ($tiles as $tile) {
            $out .= '<div class="col">'
                  . '<div class="card nvd-kpi nvd-kpi-btn" role="button" tabindex="0"'
                  . ' data-severity="' . htmlescape($tile['sev']) . '"'
                  . ' title="' . ($tile['sev'] === '' ? __s('Show all severities') : __s('Filter by this severity')) . '">'
                  . '<div class="card-body">'
                  . '<div class="nvd-kpi-value ' . $tile['cls'] . '">' . $tile['value'] . '</div>'
                  . '<div class="nvd-kpi-label">' . htmlescape($tile['label']) . '</div>'
                  . '</div></div>'
                  . '</div>';
        }

        $out .= '</div>';

        return $out;
    }

    /**
     * Build the "software vulnerabilities" table (every CVE affecting an
     * installed software version, and the assets running it).
     *
     * @since 2.1.0
     *
     * @param array $severityTally  Filled in place with severity label => count
     * @param bool  $interactive    Emit the search / filter toolbar + sortable headers
     *
     * @return string  HTML, or '' when there are no software vulnerabilities
     */
    private static function gatherSoftwareVulnList(&$severityTally, $interactive=FALSE) {

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request every vulnerability registered and the devices associated with it
         *
         *  SELECT vuln_id AS VULN_ID,
         *       GROUP_CONCAT(DISTINCT itemtype, ':', items_id ORDER BY itemtype, items_id) AS instances
         *  FROM glpi_plugin_nvd_vulnerable_software_versions, glpi_items_softwareversions
         *  WHERE glpi_plugin_nvd_vulnerable_software_versions.softwareversions_id =
         *        glpi_items_softwareversions.softwareversions_id
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => [
                    'vuln_id AS VULN_ID',
                    new QueryExpression("GROUP_CONCAT(DISTINCT `itemtype`, ':', `items_id` ORDER BY `itemtype`, `items_id`) AS instances")
                ],
                'FROM' => ['glpi_plugin_nvd_vulnerable_software_versions', 'glpi_items_softwareversions'],
                'FKEY' => ['glpi_plugin_nvd_vulnerable_software_versions' => 'softwareversions_id',
                           'glpi_items_softwareversions' => 'softwareversions_id'],
                'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $instances = explode(',', $row['instances']);
            $instance_IDs = [];

            // Sort every device into it's corresponding category
            foreach ($instances as $id => $device) {

                [$item_type, $item_id] = explode(':', $device);
                $instance_IDs[strtolower($item_type)][] = $item_id;
            }

            // Request device names from corresponding tables - excluding
            // soft-deleted (trashed) assets and, when an admin-configured
            // asset-states scope is set, assets whose state isn't in it.
            $scoped_states = PluginNvdDatabaseutils::getScopedStateIDs();

            foreach ($instance_IDs as $item_type => $IDs) {

                $table = 'glpi_' . $item_type . 's';

                $condition = ['id' => $IDs];
                if ($DB->fieldExists($table, 'is_deleted')) {
                    $condition['is_deleted'] = 0;
                }
                if (!empty($scoped_states) && $DB->fieldExists($table, 'states_id')) {
                    $condition['states_id'] = $scoped_states;
                }

                /***********************************************************************************************
                 * Request name of each still-live, in-scope device associated
                 * with a vulnerability
                 *
                 *  SELECT id, name
                 *  FROM 'glpi_' . $item_type . 's'
                 *  WHERE id IN $IDs AND is_deleted = 0 [AND states_id IN (...)]
                 **********************************************************************************************/
                $res_2 = $DB->request(['SELECT' => ['id', 'name'],
                                       'FROM' => $table,
                                       'WHERE' => $condition]);

                // Only the still-live devices survive here - a deleted asset's
                // id simply won't appear in $names.
                $names = [];
                foreach ($res_2 as $device_row) {
                    $names[$device_row['id']] = $device_row['name'];
                }
                $instance_IDs[$item_type] = $names;
            }

            $instances = [];

            // Transform names and IDs to liks to vulnerable devices in GLPI
            foreach ($instance_IDs as $item_type => $ID_names) {
                foreach ($ID_names as $ID => $name) {
                    $instances[] = '<a href="' . "{$CFG_GLPI['root_doc']}/front/$item_type.form.php?id=" . (int)$ID . '">' . htmlescape($name) . '</a>';
                }
            }

            // Skip vulnerabilities whose every installation is on a deleted asset.
            if ($instances) {
                $vulnerabilities[$row['VULN_ID']] = implode(', ', $instances);
            }
        }

        //Request information on the obtained CVE records
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        return self::displayVulnerabilityList($res, $vulnerabilities, __('Devices'), NULL, $severityTally, $interactive);
    }

    /**
     * Build the "operating system vulnerabilities" table (every CVE affecting an
     * installed OS version, and the assets running it).
     *
     * @since 2.1.0
     *
     * @param array $severityTally  Filled in place with severity label => count
     * @param bool  $interactive    Emit the search / filter toolbar + sortable headers
     *
     * @return string  HTML, or '' when there are no OS vulnerabilities
     */
    private static function gatherSystemVulnList(&$severityTally, $interactive=FALSE) {

        global $DB, $CFG_GLPI;

        /***********************************************************************************************
         * Request every operating system version and the devices associated with it
         *
         *  SELECT items_id, itemtype, operatingsystems_id, operatingsystemversions_id,
         *      operatingsystemkernelversions_id, operatingsystemservicepacks_id
         *  FROM glpi_items_operatingsystems
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['items_id', 'itemtype', 'operatingsystems_id', 'operatingsystemversions_id',
                                          'operatingsystemkernelversions_id', 'operatingsystemservicepacks_id'],
                                          'FROM' => 'glpi_items_operatingsystems']);

        $deviceConfigurations = [];
        $scoped_states = PluginNvdDatabaseutils::getScopedStateIDs();

        foreach ($res as $id => $row) {

            $item_type = $row['itemtype'];
            $ID = $row['items_id'];

            // `itemtype` is a class name (e.g. "Computer"); resolve the table and
            // form URL through GLPI so the case is right on case-sensitive MySQL.
            if (!is_string($item_type) || !class_exists($item_type) || !is_subclass_of($item_type, CommonDBTM::class)) {
                continue;
            }
            $table = $item_type::getTable();

            [$name, $version, $kernel, $kernelVersion, $servicePack] = PluginNvdDatabaseutils::requestOSdata($row);

            $installationData = PluginNvdCpe::getOSInstallationData($name, $version, $kernel, $kernelVersion, $servicePack);

            if (is_null($installationData)) { continue; }

            $configuration = $installationData['configuration'];

            // Register the configuration as seen even if the device turns out to
            // be deleted below, so the caller can tell "resolved to a deleted
            // asset" (skip the vulnerability) apart from "never resolved at all"
            // (keep showing it, labelled with the raw config - see below).
            if (!array_key_exists($configuration, $deviceConfigurations)) {
                $deviceConfigurations[$configuration] = [];
            }

            $condition = ['id' => $ID];
            if ($DB->fieldExists($table, 'is_deleted')) {
                $condition['is_deleted'] = 0;
            }
            if (!empty($scoped_states) && $DB->fieldExists($table, 'states_id')) {
                $condition['states_id'] = $scoped_states;
            }

            /***********************************************************************************************
             * Request the device's name, if it is still a live, in-scope asset
             *
             *  SELECT name FROM <item table> WHERE id = $ID AND is_deleted = 0 [AND states_id IN (...)]
             **********************************************************************************************/
            $res_2 = $DB->request(['SELECT' => 'name',
                                'FROM' => $table,
                                'WHERE' => $condition]);

            if ($res_2->numrows() != 1) { continue; } // deleted, or no longer exists

            $deviceName = $res_2->current()['name'];

            $deviceConfigurations[$configuration][] = '<a href="' . htmlescape($item_type::getFormURLWithID((int)$ID)) . '">' . htmlescape($deviceName) . '</a>';
        }

        /***********************************************************************************************
         * Request every vulnerability registered and the configurations associated with it
         *
         *  SELECT vuln_id AS VULN_ID, GROUP_CONCAT(system_configuration) AS configurations
         *  FROM glpi_plugin_nvd_vulnerable_system_versions
         *  GROUP BY vuln_id
         **********************************************************************************************/
        $res = $DB->request(['SELECT' => ['vuln_id AS VULN_ID', new QueryExpression("GROUP_CONCAT(`system_configuration`) AS configurations")],
                             'FROM' => 'glpi_plugin_nvd_vulnerable_system_versions',
                             'GROUPBY' => 'vuln_id']);

        $vulnerabilities = [];

        foreach ($res as $id => $row) {

            $configurations = explode(',', $row['configurations']);

            $devices = [];
            $anyConfigurationResolved = false;

            foreach ($configurations as $configuration) {

                if (array_key_exists($configuration, $deviceConfigurations)) {
                    $anyConfigurationResolved = true;
                    $devices = array_merge($devices, $deviceConfigurations[$configuration]);
                }
            }

            if ($devices) {
                // At least one live (non-deleted) device carries this configuration.
                $vulnerabilities[$row['VULN_ID']] = implode(', ', array_unique($devices));
            } elseif (!$anyConfigurationResolved) {
                // The configuration string itself never matched any current
                // installation (a resolution gap, not a deletion) - still show
                // the row, labelled with the raw config, so it isn't silently lost.
                $vulnerabilities[$row['VULN_ID']] = '<span class="text-muted">'
                    . htmlescape(implode(', ', array_unique($configurations))) . '</span>';
            }
            // else: the configuration matched, but every device carrying it has
            // been deleted - skip this vulnerability entirely.
        }

        //Request information on the obtained CVE records
        $res = self::requestVulnerabilities(array_keys($vulnerabilities));

        return self::displayVulnerabilityList($res, $vulnerabilities, __('Devices'), NULL, $severityTally, $interactive);
    }

    /**
     * Request list of vulnerabilities for the given item
     *
     * @since 1.0.0
     *
     * @param array $vulnerabilityIDs       IDs of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestVulnerabilities($vulnerabilityIDs) {

        if (!$vulnerabilityIDs) { return []; }

        global $DB;

        /***********************************************************************************************
        * Request information on the obtained CVE records 
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerabilities
        *  WHERE id IN array_keys($vulnerabilities)
        *  ORDER BY severity DESC
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerabilities',
                'WHERE' => ['id' => $vulnerabilityIDs],
                'ORDER' => 'base_score DESC']);

        return $res;
    }

    /**
     * Request list of description for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int $vulnID       ID of vulnerabilities to query
     *
     * @return DBmysqlIterator
     */
    private static function requestDescriptions($vulnID) {

        global $DB;

        /***********************************************************************************************
        * Request descriptions for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_descriptions
        *  WHERE vuln_id = $vulnID
        **********************************************************************************************/
        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_descriptions',
                'WHERE' => ['vuln_id' => $vulnID]]);

        return $res;
    }

    /**
     * Request list of configurations for a given vulnerability
     *
     * @since 1.0.0
     *
     * @param int   $vulnID         ID of vulnerabilities to query
     * @param array $filters        Optional query filters
     *
     * @return DBmysqlIterator
     */
    private static function requestConfigurations($vulnID, $filters) {

        global $DB;

        /***********************************************************************************************
        * Request configurations for a CVE record
        * 
        *  SELECT *
        *  FROM glpi_plugin_nvd_vulnerability_configurations
        *  WHERE vuln_id = $vulnID AND $filters
        **********************************************************************************************/
        $condition = ['vuln_id' => $vulnID];

        if (!is_null($filters)) {
            $condition = array_merge($condition, $filters);
        }

        $res = $DB->request(['FROM' => 'glpi_plugin_nvd_vulnerability_configurations',
                'WHERE' => $condition ]);

        return $res;
    }

    /**
     * Display list of vulnerabilities for the given item
     *
     * @since 1.0.0
     *
     * @param DBmysqlIterator   $DBQueryResult          Result of the CVE query
     * @param array             $vulnerableInstances    Array of vulnerability IDs and their instances
     * @param bool              $is_software            Whether or not to treat the instances as software versions or programs 
     *
     * @return string           
     */
    private static function displayVulnerabilityList($DBQueryResult, $vulnerableInstances, $instance_name, $filters=NULL, &$severityTally=NULL, $interactive=FALSE) {

        // If no vulnerabilities are found do not display anything
        if (!$vulnerableInstances) { return ''; }

        // Severity -> sort rank (higher = more severe), used for client-side sorting
        $severity_ranks = ['CRITICAL' => 4, 'HIGH' => 3, 'MEDIUM' => 2, 'LOW' => 1, 'NONE' => 0];

        $table_id = 'nvd-vuln-' . substr(md5(uniqid('', true)), 0, 8);

        $card_open  = $interactive ? '<div class="card mt-2"><div class="card-body">' : '';
        $card_close = $interactive ? '</div></div>' : '';

        $out = $card_open;

        if ($interactive) {
            $out .= '<div class="nvd-vuln-toolbar d-flex flex-wrap gap-2 align-items-center mb-2" data-target="' . $table_id . '">';
            $out .= '<div class="input-icon flex-grow-1" style="min-width:240px">';
            $out .= '<span class="input-icon-addon"><i class="ti ti-search"></i></span>';
            $out .= '<input type="text" class="form-control nvd-vuln-search" placeholder="' . __s('Search a CVE, description or asset') . '">';
            $out .= '</div>';
            $out .= '<select class="form-select nvd-vuln-severity-filter" style="max-width:180px">';
            $out .= '<option value="">' . __s('All severities') . '</option>';
            foreach (array_keys($severity_ranks) as $sev) {
                $out .= '<option value="' . htmlescape($sev) . '">' . htmlescape($sev) . '</option>';
            }
            $out .= '</select>';
            $out .= '<span class="nvd-vuln-count text-muted small"></span>';
            $out .= '</div>';
        }

        $sortable    = $interactive ? ' nvd-sortable' : '';
        $table_class = $interactive
            ? 'table table-hover table-sm card-table vuln-table'
            : 'center vuln-table';

        $table = ($interactive ? '<div class="table-responsive">' : '')
               . '<table id="' . $table_id . '" class="' . $table_class . '">';

        if (!is_null($instance_name)) {

            $table .= '<colgroup><col width="10%"/><col width="5%"/><col width="15%"/><col width="5%"/><col width="55%"/><col width="10%"/></colgroup>';

        } else {

            $table .= '<colgroup><col width="15%"/><col width="10%"/><col width="15%"/><col width="5%"/><col width="55%"/></colgroup>';
        }

        $table .=   '<thead><tr>';
        $table .=   '<th class="centered' . $sortable . '" data-sortkey="severity">' . __s('Severity') . '</th>';
        $table .=   '<th class="centered' . $sortable . '" data-sortkey="score">' . __s('Score') . '</th>';
        $table .=   '<th class="centered' . $sortable . '" data-sortkey="cve">CVE-ID</th>';
        $table .=   '<th class="centered">' . mb_chr(0x2755, 'UTF-8') . '</th>';
        $table .=   '<th class="centered">' . __s('Description') . '</th>';
        $table .=   !is_null($instance_name) ? '<th class="centered">' . htmlescape($instance_name) . '</th>' : '';
        $table .=   '</tr></thead><tbody>';

        foreach ($DBQueryResult as $id => $row) {

            $descriptions   = self::requestDescriptions($id);
            $description    = PluginNvdCverecord::getDescriptionForLanguage($descriptions);

            $configurations = self::requestConfigurations($id, $filters);
            $configuration_warning = PluginNvdCverecord::parseConfiguration($configurations, !is_null($filters));

            $severity = PluginNvdCverecord::getCvssScoreSeverity($row['base_score']);

            if (is_array($severityTally)) {
                $severityTally[$severity] = ($severityTally[$severity] ?? 0) + 1;
            }

            // base_score is a single-precision FLOAT in the DB (e.g. 9.8 reads
            // back as 9.800000190734863) - round for display.
            $has_score  = ($row['base_score'] !== null && $row['base_score'] !== '');
            $score_num  = round((float)$row['base_score'], 1);
            $score_disp = $has_score ? number_format($score_num, 1) : '—';

            $instances_html = !is_null($instance_name) ? ($vulnerableInstances[$id] ?? '') : '';
            $search_blob = mb_strtolower(trim($row['cve_id'] . ' ' . $description . ' ' . strip_tags($instances_html)));

            $table .= '<tr data-severity="' . htmlescape($severity) . '"'
                    . ' data-severity-rank="' . ($severity_ranks[$severity] ?? 0) . '"'
                    . ' data-score="' . htmlescape($score_num) . '"'
                    . ' data-cve="' . htmlescape($row['cve_id']) . '"'
                    . ' data-search="' . htmlescape($search_blob) . '">';
            // Explicit text colour per background - a bare bg-* class doesn't
            // guarantee readable contrast (bg-yellow in particular needs dark
            // text, not white; see hub §4 badge-contrast gotcha from SAC v1.1.5).
            $badge_class = [
                'CRITICAL' => 'bg-red text-white',
                'HIGH'     => 'bg-orange text-white',
                'MEDIUM'   => 'bg-yellow text-dark',
                'LOW'      => 'bg-green text-white',
                'NONE'     => 'bg-secondary text-white',
            ][$severity] ?? 'bg-secondary text-white';

            $severity_cell = $interactive
                ? '<span class="badge ' . $badge_class . '">' . htmlescape($severity) . '</span>'
                : htmlescape($severity);

            $table .= '<td class="centered">' . $severity_cell . '</td>';
            $table .= '<td class="centered">' . htmlescape($score_disp) . '</td>';
            $table .= '<td class="centered"> <a href="' . htmlescape(PluginNvdCverecord::getCveNvdUrl($row['cve_id'])) . '" target="_blank" rel="noopener">' . htmlescape($row['cve_id']) . '</a></td>';
            $table .= '<td class="centered" ' . $configuration_warning . '</td>';
            $table .= '<td class="justified">' . htmlescape($description) . '</td>';
            $table .= !is_null($instance_name) ? '<td class="centered">' . $instances_html . '</td>' : '';
            $table .= '</tr>';
        }

        $table .= '</tbody></table>';

        if ($interactive) {
            $table .= '</div>';
        }

        return $out . $table . $card_close;
    }

    /**
     * Display navigational tabs for software and operating system related vulnerabilities
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function displayNavTabs($softwareContent, $NsoftwareVulns, $systemContent, $NsystemVulns) {

        $out  = '<nav>';
        $out .= '<div class="nav nav-tabs" id="nav-tab" role="tablist">';
        $out .= '<button class="nav-link active" id="nav-software_vuln-tab" data-bs-toggle="tab" data-bs-target="#nav-software_vuln" type="button" role="tab" aria-controls="nav-software_vuln" aria-selected="true">';
        // Plain text count, not a badge/pill - suite-wide UI rule (hub §4):
        // no colored count indicators next to headings/tab labels.
        $out .= __s('Software Vulnerabilities') . ' (' . (int)$NsoftwareVulns . ')</button>';
        $out .= '<button class="nav-link" id="nav-system_vuln-tab" data-bs-toggle="tab" data-bs-target="#nav-system_vuln" type="button" role="tab" aria-controls="nav-system_vuln" aria-selected="false">';
        $out .= __s('OS Vulnerabilities') . ' (' . (int)$NsystemVulns . ')</button>';
        $out .= '</div>';
        $out .= '</nav>';
        $out .= '<div class="tab-content" id="nav-tabContent">';
        $out .= '<div class="tab-pane fade show active" id="nav-software_vuln" role="tabpanel" aria-labelledby="nav-software_vuln-tab">';
        $out .= "$softwareContent</div>";
        $out .= '<div class="tab-pane fade" id="nav-system_vuln" role="tabpanel" aria-labelledby="nav-system_vuln-tab">';
        $out .= "$systemContent</div>";
        $out .= '</div>';

        echo $out;
    }
}

?>