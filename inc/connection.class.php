<?php

class PluginNvdConnection {

    private string $baseRequestUrl;
    private array $requestHeaders;
    private array $urlParams;

    /**
     * Construct Connection headers and parameters
     * 
     * @since 1.0.0
     * 
     * @param string $baseRequestUrl    Base URL to construct the requests
     * 
     * @return void 
     */
    public function __construct($baseRequestUrl) {

        $this->baseRequestUrl = $baseRequestUrl;
        $this->requestHeaders = array();
        $this->urlParams = array();
    }

    /**
     * Assign values to URL parameters
     * 
     * @since 1.0.0
     * 
     * @param array $params     Associative array with values to assign to URL parameters
     * 
     * @return void 
     */
    public function setUrlParams(array $params) {

        foreach ($params as $param => $value) {
            $this->urlParams[$param] = urlencode(strval($value)); 
        }
    }

    /**
     * Assign values to request headers
     * 
     * @since 1.0.0
     * 
     * @param array $headers     Associative array with values to assign to request headers
     * 
     * @return void 
     */
    public function setRequestHeaders(array $headers) {

        foreach ($headers as $header => $value) {
            $this->requestHeaders[$header] = $value; 
        }
    }

    /**
     * Returns Url with parameters
     * 
     * @since 1.0.0
     * 
     * @return string 
     */
    private function getCompleteUrl() {

        $completeUrl = $this->baseRequestUrl;

        if (count($this->urlParams) != 0) {

            $completeUrl .= '?';

            foreach ($this->urlParams as $parameter => $value) {
                $completeUrl .= $parameter . (($value != Null) ? "=$value&" : '&');
            }

            $completeUrl = rtrim($completeUrl, "&");
        }

        return $completeUrl;
    }

    /**
     * Returns Array of headers and their values
     * 
     * @since 1.0.0
     * 
     * @return array
     */
    private function getRequestHeaders() {

        $headers = array();

        foreach ($this->requestHeaders as $header => $value) {
            $headers[] = "$header:$value";
        }

        return $headers;
    }

    /**
     * Launch request to url with parameters and headers
     *
     * Uses GLPI's Toolbox::callCurl() so the call honours the instance's
     * outbound proxy configuration (Setup > General > System) and GLPI's
     * curl error handling, instead of a bare curl_exec().
     *
     * @since 1.0.0
     *
     * @return array|null   decoded JSON response, or null on failure / invalid JSON
     */
    public function launchRequest() {

        $fullUrl    = $this->getCompleteUrl();
        $headers    = $this->getRequestHeaders();

        $eopts = [
            CURLOPT_TIMEOUT        => 60,
            CURLOPT_CONNECTTIMEOUT => 15,
        ];

        if (count($headers) != 0) {
            $eopts[CURLOPT_HTTPHEADER] = $headers;
        }

        $errmsg    = null;
        $curlerr   = null;
        $output    = Toolbox::callCurl($fullUrl, $eopts, $errmsg, $curlerr);

        if ($output === '' || $output === null) {
            Toolbox::logInFile(
                'nvd',
                sprintf("NVD plugin: request to %s failed (%s)\n", $fullUrl, $errmsg ?: $curlerr ?: 'no content')
            );
            return null;
        }

        return json_decode($output, true);
    }
}

?>