function addEventListeners() {
    var selectVendor        = document.getElementById("nvd_cpe_vendor_dropdown");
    var selectProduct       = document.getElementById("nvd_cpe_product_dropdown");
    var selectVendorTerms   = document.getElementById("nvd_cpe_vendor_terms_dropdown");
    var selectProductTerms  = document.getElementById("nvd_cpe_product_terms_dropdown");
    var filterVendor        = document.getElementById("nvd_cpe_vendor_filter");
    var filterProduct       = document.getElementById("nvd_cpe_product_filter");
    var applyVendorFilter   = document.getElementById("nvd_cpe_apply_vendor_filter");
    var applyProductFilter  = document.getElementById("nvd_cpe_apply_product_filter");
    var clearVendorFilter   = document.getElementById("nvd_cpe_clear_vendor_filter");
    var clearProductFilter  = document.getElementById("nvd_cpe_clear_product_filter");
    var vendorHiddenList    = document.getElementById("nvd_cpe_vendor_hidden_list");
    var productHiddenList   = document.getElementById("nvd_cpe_product_hidden_list");

    addSugestedTermsEventListener(selectVendorTerms, filterVendor);
    addSugestedTermsEventListener(selectProductTerms, filterProduct);

    addFilterApplyEventListener(filterVendor, selectVendorTerms, applyVendorFilter, selectVendor, vendorHiddenList, filterProduct, selectProductTerms, selectProduct, productHiddenList);
    addFilterApplyEventListener(filterProduct, selectProductTerms, applyProductFilter, selectProduct, productHiddenList);

    addFilterClearEventListener(filterVendor, selectVendorTerms, clearVendorFilter, selectVendor, vendorHiddenList, filterProduct, selectProductTerms, selectProduct, productHiddenList);
    addFilterClearEventListener(filterProduct, selectProductTerms, clearProductFilter, selectProduct, productHiddenList);

    selectVendor.addEventListener("change", function(){

        var vendor = this.value;

        var http = new XMLHttpRequest();

        http.onreadystatechange = function(){
            if(this.readyState == 4 && this.status == 200){
                var response = JSON.parse(this.responseText);

                resetSelects(selectProduct);

                var prodList = '';

                for (product of response){

                    prodList += `${product} `;

                    addOption(selectProduct, product);
                }

                productHiddenList.innerHTML = prodList;
            }
        }

        var root_doc = (typeof CFG_GLPI !== "undefined" && CFG_GLPI["root_doc"]) ? CFG_GLPI["root_doc"] : "";
        script_url = root_doc + "/plugins/nvd/front/softwarecpe.form.php?vendor=" + encodeURIComponent(vendor);
        http.open('GET', script_url);
        http.send();
    });
}

function addSugestedTermsEventListener(select, filter) {

    select.addEventListener("change", function(){

        var term = this.value;
        filter.value = term;
    });
}

function addFilterApplyEventListener(filter, filterSelect, apply, select, hiddenList, otherFilter=null, otherFilterSelect=null, otherSelect=null, otherHiddenList=null) {

    apply.addEventListener("click", function(){

        resetSelects(select, otherSelect, otherHiddenList);

        var term = filter.value;
        var pattern = new RegExp(".*" + escapeRegExp(term) + ".*");

        var items = hiddenList.innerHTML.split(" ");

        items.forEach(item => {

            if (pattern.test(item)) { 

                addOption(select, item);
             }
        })

        resetFilters(filter, filterSelect, otherFilter, otherFilterSelect);
    });
}

function addFilterClearEventListener(filter, filterSelect, clear, select, hiddenList, otherFilter=null, otherFilterSelect=null, otherSelect=null, otherHiddenList=null) {

    clear.addEventListener("click", function(){

        resetSelects(select, otherSelect, otherHiddenList);
        resetFilters(filter, filterSelect, otherFilter, otherFilterSelect, true);

        var items = hiddenList.innerHTML.split(" ");

        items.forEach(item => {

            addOption(select, item);
        })
    });
}

function addOption(select, value) {

    var option = document.createElement('option');
    option.value = value;
    option.innerHTML = value;

    select.appendChild(option);
}

function resetSelects(select, otherSelect=null, otherHiddenList=null) {

    select.innerHTML = select.firstChild.outerHTML;
    select.value = '-DEFAULT-';

    if (otherSelect !== null && otherHiddenList !== null) {
        otherSelect.innerHTML = otherSelect.firstChild.outerHTML;
        otherSelect.value = '-DEFAULT-';
        otherHiddenList.innerHTML = '';
    }
}

function resetFilters(filter, filterSelect, otherFilter, otherFilterSelect, removeFilterText=false) {

    filterSelect.value = '-DEFAULT-';

    if (removeFilterText) {
        filter.value = '';
    }

    if (otherFilter !== null && otherFilterSelect !== null){
        otherFilterSelect.value = '-DEFAULT-';
        otherFilter.value = '';
    }
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function changeSelectedValue(select, value) {
    select.value = value;
}

/**
 * NVD Vulnerabilities page (Tools > NVD Vulnerabilities).
 *
 * Wires the client-side search box, severity filter and sortable column
 * headers for each rendered vulnerability table. All operations act on the
 * <tr> rows already in the DOM - no server round-trip.
 */
function nvdVulnPageInit() {

    document.querySelectorAll(".nvd-vuln-toolbar").forEach(function (toolbar) {

        var table = document.getElementById(toolbar.dataset.target);
        if (!table) { return; }

        var tbody      = table.tBodies[0];
        var searchBox  = toolbar.querySelector(".nvd-vuln-search");
        var sevFilter  = toolbar.querySelector(".nvd-vuln-severity-filter");
        var countLabel = toolbar.querySelector(".nvd-vuln-count");

        function applyFilters() {
            var term = (searchBox && searchBox.value ? searchBox.value : "").trim().toLowerCase();
            var sev  = sevFilter && sevFilter.value ? sevFilter.value : "";
            var shown = 0;

            Array.prototype.forEach.call(tbody.rows, function (row) {
                var matchText = term === "" || (row.dataset.search || "").indexOf(term) !== -1;
                var matchSev  = sev === "" || row.dataset.severity === sev;
                var visible   = matchText && matchSev;
                row.style.display = visible ? "" : "none";
                if (visible) { shown++; }
            });

            if (countLabel) {
                countLabel.textContent = shown + " / " + tbody.rows.length;
            }
        }

        if (searchBox) { searchBox.addEventListener("input", applyFilters); }
        if (sevFilter) { sevFilter.addEventListener("change", applyFilters); }

        table.querySelectorAll("th.nvd-sortable").forEach(function (th) {

            th.style.cursor = "pointer";

            th.addEventListener("click", function () {

                var key = th.dataset.sortkey;
                var asc = th.dataset.sortDir !== "asc";

                table.querySelectorAll("th.nvd-sortable").forEach(function (other) {
                    if (other !== th) { delete other.dataset.sortDir; }
                });
                th.dataset.sortDir = asc ? "asc" : "desc";

                var rows = Array.prototype.slice.call(tbody.rows);

                rows.sort(function (a, b) {
                    var va, vb;
                    if (key === "score") {
                        va = parseFloat(a.dataset.score) || 0;
                        vb = parseFloat(b.dataset.score) || 0;
                    } else if (key === "severity") {
                        va = parseInt(a.dataset.severityRank, 10) || 0;
                        vb = parseInt(b.dataset.severityRank, 10) || 0;
                    } else {
                        va = (a.dataset.cve || "").toLowerCase();
                        vb = (b.dataset.cve || "").toLowerCase();
                    }
                    if (va < vb) { return asc ? -1 : 1; }
                    if (va > vb) { return asc ? 1 : -1; }
                    return 0;
                });

                rows.forEach(function (row) { tbody.appendChild(row); });
            });
        });

        applyFilters();
    });
}