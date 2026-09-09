# Changelog

All notable changes to the NVD plugin for GLPI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2026-09-09

### Fixed

- OS-vulnerability rendering built table names and form URLs by string
  concatenation (`'glpi_' . $itemtype . 's'`, `front/$itemtype.form.php`)
  using the raw PascalCase `itemtype`, producing `glpi_Computers` /
  `front/Computer.form.php`. This fails on case-sensitive MySQL (Linux):
  *Table 'glpi_Computers' doesn't exist*. Now resolved through
  `$itemtype::getTable()` and `$itemtype::getFormURLWithID()`, with a
  `class_exists` / `is_subclass_of(CommonDBTM)` guard. Affected the new
  Tools page and the Central "Vulnerabilities" tab whenever OS vulnerability
  data was present.

## [2.1.0] - 2026-09-09

### Added

- **New page: Tools → NVD Vulnerabilities.** A standalone view listing every
  CVE downloaded from the NVD API and the assets it affects, split into
  *Software* and *OS* tabs (the same data that was previously only reachable
  as a tab on the Central page).
  - Severity summary strip (Total / Critical / High / Medium / Low counts).
  - Per-table client-side search (CVE id, description, affected asset) and
    severity filter.
  - Sortable Severity / Score / CVE-ID columns.
  - Empty-state hint when no vulnerabilities have been downloaded yet.
  - Access gated on the GLPI configuration right, same as the plugin's other
    screens.

### Changed

- `PluginNvdVuln::displayForDashboard()` internals split into
  `gatherSoftwareVulnList()` / `gatherSystemVulnList()` so the Central tab and
  the new page share one code path. The Central "Vulnerabilities" tab is
  unchanged for users.
- Vulnerability tables now use `<thead>`/`<tbody>` and carry
  `data-severity` / `data-score` / `data-cve` / `data-search` attributes on
  each row.

## [2.0.0] - 2026-09-08

GLPI 11 compatibility release. Ports the upstream 1.0.0 plugin (which targeted
GLPI 10.0.6) to GLPI 11. **Requires GLPI 11.0** and is not compatible with
GLPI 10 or earlier.

### Changed

- **Requirements:** minimum GLPI raised from `10.0.6` to `11.0.0`
  (`setup.php`), max `11.99.99`.
- **Author / license metadata:** `author` now credits the GLPI 11 port by
  PGN ICT alongside the original author; `license` string normalised to the
  SPDX form `GPL-3.0-or-later` (the bundled `LICENSE` was already GPL-3.0).
- Outbound HTTP to the NVD API (`services.nvd.nist.gov`) and CIRCL
  (`cve.circl.lu`) now goes through GLPI's `Toolbox::callCurl()` instead of a
  bare `curl_exec()`. This honours the instance proxy configuration
  (*Setup > General > System*), adds connect/read timeouts (15 s / 60 s) and
  GLPI's curl error handling; failures are logged to `files/_log/nvd.log`.

### Fixed

- **Installation** failed on Linux: `require_once` paths in `hook.php` and
  `installation/install.php` used Windows `\` separators.
- **Installation** aborted with *"Executing direct queries is not allowed!"* —
  `DBmysql::queryOrDie()` / `query()` are removed in GLPI 11. All table
  creation / drop statements now use `DBmysql::doQuery()`.
- **Installation** aborted with *"Specified key was too long; max key length
  is 3072 bytes"* — the `system_configuration` column
  (`glpi_plugin_nvd_vulnerable_system_versions`) was `VARCHAR(2047)` inside a
  `UNIQUE` key, which overflows the InnoDB limit under GLPI 11's default
  `utf8mb4` charset. Reduced to `VARCHAR(255)`.
- **Fatal compile error** *"Declaration of PluginNvdVuln::canView() must be
  compatible with CommonGLPI::canView(): bool"* — added the `: bool` return
  type to `canView()` in the config, software-CPE and vulnerability classes.
- The CPE vendor/products AJAX call in `js/nvd.js` hard-coded a `/glpi/`
  document root; it now derives the root from `CFG_GLPI["root_doc"]` and
  URL-encodes the vendor.
- Plugin `<form>` actions used a relative `../plugins/nvd/...` path; they now
  use `Html::getPrefixedUrl()`.
- CVE descriptions were run through `str_replace("'", "\\'", ...)` before
  being stored. GLPI 11 parameterises inserts and escapes on output, so the
  manual escaping only persisted stray backslashes; removed.
- The `LAST_MOD_START_DATE` / `LAST_MOD_END_DATE` constants were defined with
  a trailing space in their names.

### Security

- Added `Session::checkRight()` authorisation checks to
  `front/config.form.php` (writes the NVD API key) and
  `front/softwarecpe.form.php` (writes CPE associations); previously these
  endpoints only verified that the plugin was active.
- Output escaping (`htmlescape()`) applied to values rendered by the plugin:
  the stored API key, vendor/product strings returned by the NVD API, and
  the CVE description / id / score and software / version names shown in the
  *Vulnerabilities* tab.
- The CIRCL vendor lookup URL segment is now `rawurlencode()`d.

## [1.0.0]

Original release by Carlos Borau González. Targeted GLPI 10.0.6.
See <https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN>.

[2.1.1]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[2.1.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[2.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[1.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
