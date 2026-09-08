# Changelog

All notable changes to the NVD plugin for GLPI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[1.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
