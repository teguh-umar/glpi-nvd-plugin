<?php

use Glpi\Plugin\Hooks;

define('PLUGIN_NVD_VERSION', '2.4.2');
define('PLUGIN_NVD_MIN_GLPI', '11.0.0');
define('PLUGIN_NVD_MAX_GLPI', '11.99.99');

define('PLUGIN_NVD_DIR', __DIR__);

/**
 * Init the hooks of the plugin and register plugin classes
 * 
 * @since 1.0.0
 *
 * @return void
 */
function plugin_init_nvd() {
   global $PLUGIN_HOOKS;

   $PLUGIN_HOOKS['csrf_compliant']['nvd'] = true;

   Plugin::registerClass(PluginNvdConfig::class, ['addtabon' => 
      [Config::class
   ]]);

   Plugin::registerClass(PluginNvdVuln::class, ['addtabon' => 
      [Central::class,
       Computer::class,
       Phone::class,
       Software::class
   ]]);

   Plugin::registerClass(PluginNvdSoftwarecpe::class, ['addtabon' =>
      [Software::class
   ]]);

   Plugin::registerClass(PluginNvdMenu::class);

   // Add a "NVD Vulnerabilities" entry to the core Tools sector
   $PLUGIN_HOOKS[Hooks::MENU_TOADD]['nvd'] = ['tools' => 'PluginNvdMenu'];

   $PLUGIN_HOOKS[Hooks::ADD_JAVASCRIPT]['nvd'] = 'js/nvd.js';
   $PLUGIN_HOOKS[Hooks::ADD_CSS]['nvd'] = 'css/nvd.css';

}

/**
 * Get the name and the version of the plugin - Needed
 * 
 * @since 1.0.0
 *
 * @return array
 */
function plugin_version_nvd() {
   return [
      'name'           => 'NVD',
      'shortname'      => 'nvd',
      'version'        => PLUGIN_NVD_VERSION,
      'author'         => 'Carlos Borau González; GLPI 11 port by PGN ICT',
      'license'        => 'GPL-3.0-or-later',
      'homepage'       => 'https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN',
      'requirements'   => [
         'glpi'   => [
            'min' => PLUGIN_NVD_MIN_GLPI,
            'max' => PLUGIN_NVD_MAX_GLPI
         ]
      ]
   ];
}

/**
 * Optional : check prerequisites before install : may print errors or add to message after redirect
 * 
 * @since 1.0.0
 *
 * @return boolean
 * 
 * @todo
 */
function plugin_nvd_check_prerequisites() {
   
    // Check that the GLPI version is compatible
    if (version_compare(GLPI_VERSION, PLUGIN_NVD_MIN_GLPI, 'lt')) {

        echo __('This plugin Requires GLPI >=') . PLUGIN_NVD_MIN_GLPI;

        return false;
    }

    return true;
}

/**
 * Check configuration process for plugin : need to return true if succeeded
 * Can display a message only if failure and $verbose is true
 * 
 * @since 1.0.0
 *
 * @param boolean $verbose Enable verbosity. Default to false
 *
 * @return boolean
 */
function plugin_nvd_check_config($verbose = false) {

   return true;
}

/**
 * Optional: defines plugin options.
 * 
 * @since 1.0.0
 *
 * @return array
 */
function plugin_nvd_options() {
   return [
      Plugin::OPTION_AUTOINSTALL_DISABLED => true,
   ];
}