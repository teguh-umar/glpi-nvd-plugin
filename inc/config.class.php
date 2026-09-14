<?php

class PluginNvdConfig extends CommonGLPI {

    /**
     * Check if can view item
     *
     * @since 1.0.0
     *
     * @return boolean
     */
    static function canView(): bool {
        
        return Config::canView();
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

        return self::createTabEntry(__('NVD Plugin'));
    }

    /**
     * Display tab content for config tab
     *
     * @since 1.0.0
     *
     * @param CommonGLPI $item       Config item
     * @param int $tabnum
     * @param int $withtemplate
     *
     * @return boolean
     */
    static function displayTabContentForItem(CommonGLPI $item, $tabnum=1, $withtemplate=0) {

        if ($item::getType() === Config::getType()) {
            self::displayConfig();
        }
        
        return true;
    }

    /**
     * Display tab content for config tab
     *
     * @since 1.0.0
     *
     * @return void
     */
    private static function displayConfig() {

        $currentApiKey       = PluginNvdDatabaseutils::getNvdApiKey();
        $scopedStates        = PluginNvdDatabaseutils::getScopedStateIDs();
        $vulnTabVisibility   = PluginNvdDatabaseutils::getVulnTabVisibility();
        $allStates           = PluginNvdDatabaseutils::getAllStates();

        $out  = '<form action="' . Html::getPrefixedUrl('/plugins/nvd/front/config.form.php') . '" method="POST">';
        $out .= Html::hidden('_glpi_csrf_token', array('value' => Session::getNewCSRFToken()));

        if ($currentApiKey != NULL) {
            $out .= Html::hidden('oldApiKey', array('value' => $currentApiKey));
        }

        $out .= '<div class="nvd_cpe_div">';
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<b class="nvd_cpe_title">' . __('NVD API key') . ':</b></div>';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<input required class="nvd_cpe_wide_textinput" type="text" id="nvd_api_key" name="newApiKey" value="' . htmlescape($currentApiKey) . '"></div></div>';
        $out .= '</div></div>';

        $out .= '<div class="nvd_cpe_div horizontal_ruler"></div>';

        $out .= '<div class="nvd_cpe_div">';
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<b class="nvd_cpe_title">' . __('Asset states in scope for CVE correlation', 'nvd') . ':</b></div></div>';
        $out .= '<div class="nvd_cpe_stack_row"><div>'
              . __s('Only Computers/Phones currently in one of the selected states are matched against CVEs and shown in vulnerability lists. Select none to keep every state in scope (default).')
              . '</div></div>';
        $out .= '<div class="nvd_cpe_stack_row"><div><select name="scoped_states[]" multiple class="nvd_cpe_wide_dropdown" style="height:8em">';
        foreach ($allStates as $state_id => $state_name) {
            $selected = in_array($state_id, $scopedStates, true) ? 'selected ' : '';
            $out .= '<option ' . $selected . 'value="' . (int) $state_id . '">' . htmlescape($state_name) . '</option>';
        }
        $out .= '</select></div></div>';
        $out .= '</div></div>';

        $out .= '<div class="nvd_cpe_div horizontal_ruler"></div>';

        $out .= '<div class="nvd_cpe_div">';
        $out .= '<div class="nvd_cpe_stack_collumn">';
        $out .= '<div class="nvd_cpe_stack_row">';
        $out .= '<div class="nvd_cpe_row">';
        $out .= '<b class="nvd_cpe_title">' . __('Who can see the Vulnerabilities tab', 'nvd') . ':</b></div></div>';
        $out .= '<div class="nvd_cpe_stack_row"><div>'
              . __s('The CPE Association tab and this configuration tab always require the GLPI configuration (Setup) right, regardless of this setting.')
              . '</div></div>';
        $out .= '<div class="nvd_cpe_stack_row"><div><select name="vuln_tab_visibility" class="nvd_cpe_wide_dropdown">';
        $out .= '<option value="config_only" ' . ($vulnTabVisibility === 'config_only' ? 'selected ' : '') . '>' . __s('Only users with the GLPI configuration (Setup) right - default') . '</option>';
        $out .= '<option value="asset_read" ' . ($vulnTabVisibility === 'asset_read' ? 'selected ' : '') . '>' . __s('Anyone who can already view the Computer, Phone or Software') . '</option>';
        $out .= '</select></div></div>';
        $out .= '</div></div>';

        $out .= '<div class="nvd_cpe_div">';
        $out .= '<input type="submit" class="btn btn-primary" value="' . __('Save NVD plugin configuration') . '"></div>';
        $out .= '</form>';

        echo $out;
    }
}

?>