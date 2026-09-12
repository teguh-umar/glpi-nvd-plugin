<?php

include ("../../../inc/includes.php");

// Check if plugin is activated...
$plugin = new Plugin();
if (!$plugin->isInstalled('nvd') || !$plugin->isActivated('nvd')) {
   Html::displayNotFoundError();
}

// Managing CPE associations for a software requires the right to update software
Session::checkRight('software', UPDATE);

// Check if request is loocking for vendor products or wanting to set/update software vendor and product cpe names
if (isset($_GET['vendor'])) {

    $vendor = $_GET['vendor'];

    $output = getProductsForVendor($vendor);

    // getProductsForVendor() / launchRequest() return null when the CIRCL
    // vendor/product directory (cve.circl.lu) could not be reached - respond
    // with an empty list rather than a fatal error the caller's JS can't parse.
    $products = is_array($output['product'] ?? null) ? $output['product'] : [];

    echo json_encode($products);

} elseif (isset($_POST['softwares_id']) and isset($_POST['vendor']) and isset($_POST['product']) and isset($_POST['action'])) {

    $softwares_id = $_POST['softwares_id'];

    // The manual vendor/product fields (printManualVendorProductOverride())
    // take priority over the CIRCL-backed dropdowns - they're the only way
    // to set a CPE at all when cve.circl.lu can't be reached.
    $vendor  = normalizeCPEToken($_POST['vendor_manual'] ?? '', $_POST['vendor'] ?? '');
    $product = normalizeCPEToken($_POST['product_manual'] ?? '', $_POST['product'] ?? '');
    $action = $_POST['action'];

    if ($vendor === '' || $product === '') {
        Session::addMessageAfterRedirect(__s('Vendor and product are required to set a CPE association.', 'nvd'), false, ERROR);
        Html::redirect("{$CFG_GLPI['root_doc']}/front/software.form.php?id=$softwares_id");
    }

    switch($action) {
        case 'insert':
            insertSoftwareCPENames($softwares_id, $vendor, $product);
            break;
        case 'update':
            updateSoftwareCPENames($softwares_id, $vendor, $product);
            break;
    };

    Html::redirect("{$CFG_GLPI['root_doc']}/front/software.form.php?id=$softwares_id");

} else {
    Html::redirect("{$CFG_GLPI['root_doc']}/front/software.php");
}

/**
 * Resolve a CPE vendor/product value from the manual override field first
 * (see PluginNvdSoftwarecpe::printManualVendorProductOverride()), falling
 * back to the CIRCL-backed dropdown value, and normalise it to the
 * lowercase-with-underscores form NIST CPE names use.
 *
 * @since 2.4.4
 *
 * @param string $manual    Value of the manual text input (vendor_manual / product_manual)
 * @param string $dropdown  Value of the <select> (vendor / product); '-DEFAULT-' means "none selected"
 *
 * @return string  Normalised token, or '' if neither source provided one
 */
function normalizeCPEToken($manual, $dropdown) {

    $value = trim((string) $manual);

    if ($value === '') {
        $value = trim((string) $dropdown);
        if ($value === '-DEFAULT-') {
            $value = '';
        }
    }

    if ($value === '') {
        return '';
    }

    return strtolower(str_replace([' ', '-'], '_', $value));
}

/**
 * Request products from CVE MITRE for a given vendor
 *
 * @since 1.0.0
 *
 * @param string $vendor    Software vendor for which to retrieve products
 *
 * @return string server JSON response
 */
function getProductsForVendor($vendor) {

    $CVEConn = new PluginNvdCveconnection($vendor);

    $output = $CVEConn->launchRequest();

    return $output;
}

/**
 * Insert new CPE vendor and product association with given software
 *
 * @since 1.0.0
 *
 * @param int       $softwares_id       ID of the software for which to create the association
 * @param string    $vendor             CPE vendor name for the given software
 * @param string    $product            CPE product name for the given software
 *
 * @return void
 */
function insertSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;

    /***********************************************************************************************
     * Create CPE vendor and product name association for given software
     * 
     *  INSERT INTO glpi_plugin_nvd_cpe_software_associations 
     *  (softwares_id, vendor_name, product_name) VALUES ($softwares_id, $vendor, $product)
     **********************************************************************************************/
    $DB->insert(
        'glpi_plugin_nvd_cpe_software_associations', [
            'softwares_id' => $softwares_id,
            'vendor_name' => $vendor,
            'product_name' => $product
        ]
    );
}

/**
 * Update CPE vendor and product names association for given software
 *
 * @since 1.0.0
 *
 * @param int       $softwares_id       ID of the software for which to update the association
 * @param string    $vendor             CPE vendor name for the given software
 * @param string    $product            CPE product name for the given software
 *
 * @return void
 */
function updateSoftwareCPENames($softwares_id, $vendor, $product) {

    global $DB;

    /***********************************************************************************************
     * Update CPE vendor and product name association for given software
     * 
     *  UPDATE glpi_plugin_nvd_cpe_software_associations 
     *  SET vendor_name = $softwares_id, product_name = $product
     *  WHERE softwares_id = $softwares_id
     **********************************************************************************************/
    $DB->update(
        'glpi_plugin_nvd_cpe_software_associations', [
            'vendor_name' => $vendor,
            'product_name' => $product
        ], [
            'softwares_id' => $softwares_id
        ]
    );
}

?>