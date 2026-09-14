<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

// Only users who can update the GLPI configuration may change the NVD API key
Session::checkRight('config', UPDATE);

if (isset($_POST['newApiKey'])) {

    $newApiKey = $_POST['newApiKey'];
    $oldApiKey = (isset($_POST['oldApiKey'])) ? $_POST['oldApiKey'] : NULL;

    // A <select multiple> with nothing picked doesn't submit the field at
    // all - absent means "no scope filter" (every asset state in scope).
    $scopedStates = array_filter(array_map('intval', $_POST['scoped_states'] ?? []));
    $scopedStatesValue = implode(',', $scopedStates);

    $vulnTabVisibility = (($_POST['vuln_tab_visibility'] ?? '') === 'asset_read') ? 'asset_read' : 'config_only';

    updateNvdConfig($newApiKey, $oldApiKey, $scopedStatesValue, $vulnTabVisibility);
}

Html::redirect("{$CFG_GLPI['root_doc']}/front/config.form.php");

/**
 * Update the NVD plugin's single config row: API key, asset-states scope
 * and Vulnerabilities-tab visibility.
 *
 * @since 1.0.0
 *
 * @param string $newApiKey            New NVD API key
 * @param string $oldApiKey            Old NVD API key ('' / null on first save)
 * @param string $scopedStatesValue    Comma-separated glpi_states ids, '' = no filter
 * @param string $vulnTabVisibility    'config_only' | 'asset_read'
 *
 * @return void
 */
function updateNvdConfig($newApiKey, $oldApiKey, $scopedStatesValue, $vulnTabVisibility) {

    global $DB;

    $data = [
        'api_key'             => $newApiKey,
        'scoped_states'       => $scopedStatesValue,
        'vuln_tab_visibility' => $vulnTabVisibility,
    ];

    if ($oldApiKey == NULL) {

        $DB->insert('glpi_plugin_nvd_config', $data);

    } else {

        $DB->update('glpi_plugin_nvd_config', $data, ['api_key' => $oldApiKey]);
    }
}

?>