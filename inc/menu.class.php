<?php

/**
 * Menu entry for the NVD plugin.
 *
 * Registered via $PLUGIN_HOOKS['menu_toadd']['nvd'] = ['tools' => 'PluginNvdMenu']
 * in setup.php, which appends a single entry to GLPI's core "Tools" sector.
 *
 * @since 2.1.0
 */
class PluginNvdMenu extends CommonGLPI {

    public static $rightname = 'config';

    /**
     * Menu label shown in the sidebar.
     *
     * @return string
     */
    public static function getMenuName() {
        return __('NVD Vulnerabilities', 'nvd');
    }

    /**
     * Icon shown next to the menu entry.
     *
     * @return string
     */
    public static function getIcon() {
        return 'ti ti-shield-lock';
    }

    /**
     * Only users allowed to view the GLPI configuration (same gate as the
     * plugin's config tab) may see the entry.
     *
     * @return bool
     */
    public static function canView(): bool {
        return Config::canView();
    }

    /**
     * Menu content: a single page under Tools.
     *
     * @return array
     */
    public static function getMenuContent() {

        if (!self::canView()) {
            return false;
        }

        $menu = [
            'title' => self::getMenuName(),
            'page'  => '/plugins/nvd/front/vulnerability.php',
            'icon'  => self::getIcon(),
        ];

        return $menu;
    }
}
