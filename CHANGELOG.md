# Changelog

All notable changes to the NVD plugin for GLPI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.6] - 2026-09-13

### Fixed

- Suite-wide UI rule (no colored pill/badge count next to a heading/tab
  label - low contrast, flagged by the user on another plugin): the
  Software/OS Vulnerabilities sub-tab labels now show a plain
  `Label (N)` count instead of a `badge bg-primary` pill.
- Severity badges in the vulnerability table (`CRITICAL`/`HIGH`/`MEDIUM`/
  `LOW`/`NONE`) now set an explicit text colour per background instead of
  relying on the bare `bg-*` class - in particular `bg-yellow` (MEDIUM) now
  pairs with `text-dark` rather than an unspecified/white text colour that
  made it hard to read (same bug class SAC found and fixed in their
  v1.1.5: a badge with no explicit text colour silently inherits the wrong
  one).

## [2.4.5] - 2026-09-13

### Added

- **The CPE Association tab's vendor dropdown now falls back to GLPI's own
  Manufacturers list** (Setup > Dropdowns > Manufacturers) when
  `cve.circl.lu` is unreachable, instead of an empty dropdown. This is
  local, always-available data - no external dependency.
- Vendor values (whether picked from that fallback dropdown or typed into
  the manual field) are cleaned up before being saved: trailing corporate
  suffixes (`Corporation`, `Corp.`, `Inc.`, `Ltd.`, `LLC`, `Systems`,
  `Technology`, `Team`, etc., stripped up to 3 times, plus stray trailing
  commas/periods) are removed to get closer to the real NIST CPE vendor
  token - e.g. GLPI's "Wacom Technology Corp." -> `wacom`, "Microsoft
  Corporation" -> `microsoft`. This is a heuristic, not a lookup, so it
  won't always be exact (e.g. "Oracle America" -> `oracle_america`, not
  `oracle`) - the manual field is there to correct it by hand when needed.
- New `PluginNvdDatabaseutils::getManufacturerNames()`.

## [2.4.4] - 2026-09-13

### Added

- **Manual CPE vendor/product entry.** Confirmed on this deployment:
  `cve.circl.lu` (the vendor/product directory behind the CPE Association
  tab's dropdowns) is not reachable at all from this network, which left the
  dropdowns permanently empty with no way to assign a CPE through the UI.
  A "Or type the CPE vendor/product manually" section is now always shown
  alongside the dropdowns, with a link to NVD's own CPE dictionary search
  (nvd.nist.gov/products/cpe/search). The manually typed value wins over the
  dropdown selection when both are present, and is normalised to lowercase
  with underscores (NIST CPE's convention).
- The vendor/product `<select>` elements are no longer `required`, since an
  unreachable directory previously left them with nothing selectable and
  the form could not be submitted at all via the browser's own HTML5
  validation. Vendor/product are still required server-side (from either
  source) before a CPE association is saved.

## [2.4.3] - 2026-09-13

### Fixed

- **Fatal error opening the CPE Association tab on a Software item** when the
  CIRCL vendor/product directory (`cve.circl.lu` - a separate service from
  the NVD API, used only to populate the vendor/product dropdowns) could not
  be reached: `PluginNvdConnection::launchRequest()` returns `null` on any
  connection failure, and the code indexed straight into it
  (`$output['vendor']`) with no check, causing a PHP warning followed by a
  fatal `implode(): ... must be of type array, string given`.
  - `PluginNvdSoftwarecpe::displayForSoftware()` and the
    `front/softwarecpe.form.php` AJAX endpoint now treat a failed lookup as
    an empty vendor/product list instead of crashing.
  - The CPE tab shows a warning banner when the directory is unreachable,
    pointing at `files/_log/nvd.log` and the instance's outbound proxy
    configuration.
  - `printVendorAndProductDropdowns()` defensively casts its inputs to
    arrays as a second line of defence.
- This does not affect CVE matching itself (the NVD API call used by
  `UpdateVulnTask`) - only the vendor/product picker used when manually
  assigning a CPE to a software.

## [2.4.2] - 2026-09-12

### Changed

- **Soft-deleted (trashed) assets are no longer treated as live inventory.**
  A GLPI "delete" is a trash move (`is_deleted = 1`), not an immediate purge,
  so a deleted Computer/Phone's installation rows stayed visible to nvd
  indefinitely. Now:
  - The cron (`requestAllSoftwareInstallations()` /
    `requestAllOSInstallations()`) excludes installations that belong only
    to a deleted asset when deciding what's currently installed, so
    vulnerabilities that no longer affect any live asset get pruned on the
    next run.
  - The Central tab / Tools page / other-devices lists
    (`gatherSoftwareVulnList()` / `gatherSystemVulnList()`) exclude deleted
    assets from the "affected devices" column, and drop a vulnerability
    entirely from the list if every device carrying it is deleted. A
    vulnerability whose configuration never resolved to *any* installation
    (a genuine matching gap, unrelated to deletion) still shows, labelled
    with the raw configuration.
  - Opening a deleted item's own **Vulnerabilities** tab now shows a notice
    ("in the trash, tracking suspended") and a 0 count instead of
    potentially-stale data - this was the exact scenario in the bug report
    (a deleted Computer still listing OS vulnerabilities).
- `getNextId()`'s replacement pattern (2.4.1) was reused here too:
  `PluginNvdDatabaseutils::getDeletedItemIDs($itemtype)` reads `is_deleted`
  straight off the resolved GLPI table, guarded by `$DB->fieldExists()`.

## [2.4.1] - 2026-09-12

### Fixed

- **Data-integrity bug: new CVEs' descriptions/configurations/version-links
  could be stored under the wrong `vuln_id`, or none at all** — visible as
  CVE rows with a correct CVE-ID / score / severity but an empty
  **Description** column.
  - Root cause: `PluginNvdUpdatevuln` tracked "the next vulnerability id" by
    calling `PluginNvdDatabaseutils::getNextId()`, which read
    `INFORMATION_SCHEMA.TABLES.AUTO_INCREMENT` with a **hardcoded
    `TABLE_SCHEMA = 'glpi'`**. On any instance whose database is not
    literally named `glpi` (e.g. `itsm`), the query matches no rows and
    `getNextId()` returns `null`; the manually tracked counter then starts
    fresh (`null++` → `1`) on every cron run instead of following the
    table's real auto-increment, so it drifts from the id MySQL actually
    assigned to the new `glpi_plugin_nvd_vulnerabilities` row. Descriptions,
    configurations and the software/OS version links were all inserted
    under that drifted id.
  - Fix: removed the manual counter and `getNextId()` entirely.
    `insertNewVulnerabilities()` now reads the real id straight off the
    insert with `DBmysql::insertId()`. Also skips the description/
    configuration/link inserts if the vulnerability insert itself failed
    (it previously proceeded regardless).

### Upgrade note

This does not repair vulnerabilities already stored by a prior version.
After deploying 2.4.1, clear the plugin's downloaded data and let the next
`UpdateVulnTask` run repopulate it correctly:

```sql
TRUNCATE glpi_plugin_nvd_vulnerabilities;
TRUNCATE glpi_plugin_nvd_vulnerability_descriptions;
TRUNCATE glpi_plugin_nvd_vulnerability_configurations;
TRUNCATE glpi_plugin_nvd_vulnerable_software_versions;
TRUNCATE glpi_plugin_nvd_vulnerable_system_versions;
```

(`glpi_plugin_nvd_config` — the API key — and
`glpi_plugin_nvd_cpe_software_associations` — your manual CPE mappings — are
untouched by this bug and should **not** be truncated.)

## [2.4.0] - 2026-09-10

### Changed

- **Much wider operating-system recognition for CVE matching.**
  `PluginNvdCpe::classifyLinuxInstallation()` previously only handled Debian,
  Ubuntu and an exact `"Redhat"` string. It now maps the GLPI OS name to the
  right NIST CPE for: Red Hat Enterprise Linux (`"Red Hat"` / `"RedHat"` /
  `"RHEL"`), Oracle Linux, CentOS, Rocky Linux, AlmaLinux, SUSE / SLES,
  openSUSE, Amazon Linux (2 / 2023), plus the existing Ubuntu and Debian.
  - The Ubuntu CPE vendor was corrected from `ubuntu` to `canonical`.
  - Enterprise Linux distros are queried at their **major** version
    (`cpe:2.3:o:oracle:linux:9`), Ubuntu/Debian at **major.minor**.
- **Dirty version strings are cleaned** before building the CPE — parenthetical
  code names (`(Core)`, `(Jammy Jellyfish)`), the `LTS` marker and a leading
  product name (`Oracle Linux 9.4`) are stripped.
- When a host's kernel dropdown is empty, the OS family is inferred from the
  name instead of skipping the host.

### Upgrade note

The stored `system_configuration` strings change format for the newly
recognised distros. Run the **UpdateVulnTask** automatic action after
deploying — the task prunes the old rows and re-scans.

## [2.3.4] - 2026-09-10

### Fixed

- The count badges on the "Software Vulnerabilities" / "OS Vulnerabilities"
  sub-tabs were unreadable (`bg-secondary`, low contrast). They now use a
  solid primary badge with white text.

## [2.3.3] - 2026-09-10

### Fixed

- The **Score** column showed the raw single-precision `FLOAT` value
  (e.g. `9.800000190734863`) instead of `9.8`. Scores are now rounded to one
  decimal for display and in the sort key; a missing score shows `—`.
- An OS vulnerability whose affected version can no longer be matched to a
  live installation now still renders (labelled with the CPE configuration
  string in muted text) instead of an empty row.

## [2.3.2] - 2026-09-10

### Fixed

- **`js/nvd.js` and `css/nvd.css` returned 404 on GLPI 11** — the page had no
  interactivity (clickable KPI tiles, search, filter, column sort) and no
  custom styling. GLPI 11 only serves plugin static assets from a `public/`
  subdirectory, so the files moved to `public/js/nvd.js` and
  `public/css/nvd.css`. The `ADD_JAVASCRIPT` / `ADD_CSS` hook paths are
  unchanged (`js/nvd.js`, `css/nvd.css` — no `public/` prefix in the URL).
- `js/nvd.js` now self-initialises on `.nvd-vuln-page` (on `DOMContentLoaded`
  or immediately if already parsed) and `nvdVulnPageInit()` is idempotent, so
  it no longer depends on the inline bootstrap running after the script.

## [2.3.1] - 2026-09-10

### Fixed

- `PluginNvdCverecord::getDescriptionForLanguage()` warned
  *"Undefined array key 'en'"* and returned null when a stored CVE had no
  English description (or none matching the GLPI language). It now falls back
  to English, then to any available description, then to an empty string.

## [2.3.0] - 2026-09-10

### Added

- The severity KPI tiles on the NVD Vulnerabilities page are now clickable:
  clicking Critical / High / Medium / Low filters both vulnerability tables
  to that severity; clicking the active tile (or **Total**) clears the
  filter. Keyboard accessible (Enter / Space).

## [2.2.1] - 2026-09-10

### Fixed

- The empty-state message on the NVD Vulnerabilities page showed a literal
  `&gt;` instead of `>` (the string contained a pre-escaped entity that
  `__s()` escaped a second time).

## [2.2.0] - 2026-09-10

### Changed

- **NVD Vulnerabilities page restyled** to match the GLPI 11 look (Tabler
  cards, KPI tiles, badges) instead of the plugin's own bare CSS:
  - Severity summary rendered as a row of `card` KPI tiles
    (Total / Critical / High / Medium / Low) with GLPI's semantic colours.
  - Each vulnerability table wrapped in a `card`; toolbar uses GLPI form
    controls (`form-control`, `form-select`, search icon); tables use
    `table table-hover table-sm`.
  - Severity column shown as a coloured badge.
  - Empty state shown as a card.
  - The page no longer depends on `css/nvd.css` loading — it ships a small
    inline `<style>` and relies on GLPI's bundled Tabler classes.
- The Central "Vulnerabilities" tab keeps its previous plain-table look.

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

[2.4.6]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.5]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.4]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.3]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.2]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.1]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.4.0]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.3.4]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.3.3]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.3.2]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.3.1]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.3.0]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.2.1]: https://github.com/teguh-umar/glpi-nvd-plugin
[2.2.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[2.1.1]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[2.1.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[2.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
[1.0.0]: https://github.com/Carlos-Borau/GLPI-NVD-PLUGIN
