package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type VirusTotalResponse struct {
	ResponseCode int      `json:"response_code"`
	Subdomains   []string `json:"subdomains"`
	Resolutions  []struct {
		IPAddress string `json:"ip_address"`
		Hostname  string `json:"hostname"`
	} `json:"resolutions"`
	UndetectedURLs []interface{} `json:"undetected_urls"`
}

type APIClient struct {
	apiKeys      []string
	currentKey   int
	requestCount int
	httpClient   *http.Client
}

func NewAPIClient(apiKeys []string) *APIClient {
	return &APIClient{
		apiKeys:    apiKeys,
		currentKey: 0,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *APIClient) GetNextAPIKey() string {
	c.requestCount++
	if c.requestCount >= 5 {
		c.requestCount = 0
		c.currentKey = (c.currentKey + 1) % len(c.apiKeys)
	}
	return c.apiKeys[c.currentKey]
}

func (c *APIClient) FetchDomainReport(domain string) (*VirusTotalResponse, error) {
	apiKey := c.GetNextAPIKey()
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	apiURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
		url.QueryEscape(apiKey), url.QueryEscape(domain))

	fmt.Printf("\nFetching data for domain: %s (using API key %d)\n",
		domain, c.currentKey+1)

	resp, err := c.httpClient.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error fetching data for domain %s: %v", domain, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d for domain %s", resp.StatusCode, domain)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var vtResponse VirusTotalResponse
	if err := json.Unmarshal(body, &vtResponse); err != nil {
		fmt.Printf("Raw API response for %s:\n%s\n", domain, string(body))
		return nil, fmt.Errorf("error parsing JSON response: %v", err)
	}

	return &vtResponse, nil
}

func Countdown(seconds int) {
	for i := seconds; i > 0; i-- {
		fmt.Printf("Waiting for %d seconds...\r", i)
		time.Sleep(1 * time.Second)
	}
	fmt.Print("\n")
}

func ExtractSubdomains(response *VirusTotalResponse, domain string) []string {
	subdomains := make(map[string]bool)

	for _, subdomain := range response.Subdomains {
		subdomains[subdomain] = true
	}

	for _, resolution := range response.Resolutions {
		if resolution.Hostname != "" {
			subdomains[resolution.Hostname] = true
		}
	}

	for _, urlItem := range response.UndetectedURLs {
		switch v := urlItem.(type) {
		case []interface{}:
			if len(v) > 0 {
				if urlStr, ok := v[0].(string); ok {
					if parsedURL, err := url.Parse(urlStr); err == nil {
						if parsedURL.Host != "" {
							subdomains[parsedURL.Host] = true
						}
					}
				}
			}
		case string:
			if parsedURL, err := url.Parse(v); err == nil {
				if parsedURL.Host != "" {
					subdomains[parsedURL.Host] = true
				}
			}
		case float64:
			continue
		default:
			continue
		}
	}

	var result []string
	for subdomain := range subdomains {
		if isValidSubdomain(subdomain, domain) {
			result = append(result, subdomain)
		}
	}

	return result
}

func ExtractIPs(response *VirusTotalResponse) []string {
	ips := make(map[string]bool)

	for _, resolution := range response.Resolutions {
		if resolution.IPAddress != "" {
			ips[resolution.IPAddress] = true
		}
	}

	var result []string
	for ip := range ips {
		result = append(result, ip)
	}

	return result
}

func isValidSubdomain(subdomain, domain string) bool {
	subdomain = strings.TrimSuffix(subdomain, ".")
	domain = strings.TrimSuffix(domain, ".")
	return strings.HasSuffix(subdomain, "."+domain) || subdomain == domain
}

func isValidIP(ip string) bool {
	ipRegex := regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	return ipRegex.MatchString(ip)
}

func WriteToFile(filename string, data []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, item := range data {
		if _, err := writer.WriteString(item + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func TestAPIKeys(apiKeys []string) {
	fmt.Println("Testing API keys...")

	for i, apiKey := range apiKeys {
		fmt.Printf("Testing API key %d: %s...\n", i+1, apiKey[:8]+"...")

		testURL := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=www.virustotal.com",
			url.QueryEscape(apiKey))

		resp, err := http.Get(testURL)
		if err != nil {
			fmt.Printf("API key %d failed: Network error - %v\n", i+1, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("API key %d failed: Error reading response - %v\n", i+1, err)
				continue
			}

			var testResponse VirusTotalResponse
			if err := json.Unmarshal(body, &testResponse); err != nil {
				fmt.Printf("API key %d failed: Invalid JSON response - %v\n", i+1, err)
				continue
			}

			if testResponse.ResponseCode == 1 {
				fmt.Printf("API key %d working correctly\n", i+1)
			} else {
				fmt.Printf("API key %d responded but no data found (response_code: %d)\n", i+1, testResponse.ResponseCode)
			}
		} else if resp.StatusCode == 403 {
			fmt.Printf("API key %d failed: Forbidden (403) - Invalid API key\n", i+1)
		} else if resp.StatusCode == 429 {
			fmt.Printf("API key %d rate limited (429) - Try again later\n", i+1)
		} else {
			fmt.Printf("API key %d failed: HTTP %d\n", i+1, resp.StatusCode)
		}

		time.Sleep(2 * time.Second)
	}
	fmt.Println("API key testing completed.\n")
}

func ReadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	return domains, scanner.Err()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <domain or file_with_domains>\n", os.Args[0])
		fmt.Printf("       %s --test (to test API keys)\n", os.Args[0])
		os.Exit(1)
	}

	apiKeys := []string{"{KEY}", "{KEY}", "{KEY}"}

	if os.Args[1] == "--test" {
		TestAPIKeys(apiKeys)
		return
	}

	client := NewAPIClient(apiKeys)

	var domains []string
	input := os.Args[1]

	if _, err := os.Stat(input); err == nil {
		domains, err = ReadDomainsFromFile(input)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", input, err)
			os.Exit(1)
		}
	} else {
		domains = []string{input}
	}

	allSubdomains := make(map[string]bool)
	allIPs := make(map[string]bool)

	for i, domain := range domains {
		fmt.Printf("\nProcessing domain %d/%d: %s\n", i+1, len(domains), domain)

		response, err := client.FetchDomainReport(domain)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		if response.ResponseCode != 1 {
			fmt.Printf("No data found for domain: %s\n", domain)
			continue
		}

		subdomains := ExtractSubdomains(response, domain)
		ips := ExtractIPs(response)

		for _, subdomain := range subdomains {
			allSubdomains[subdomain] = true
		}
		for _, ip := range ips {
			if isValidIP(ip) {
				allIPs[ip] = true
			}
		}

		fmt.Printf("Found %d subdomains and %d IPs for %s\n",
			len(subdomains), len(ips), domain)

		if i < len(domains)-1 {
			Countdown(20)
		}
	}

	var subdomainSlice []string
	for subdomain := range allSubdomains {
		subdomainSlice = append(subdomainSlice, subdomain)
	}

	var ipSlice []string
	for ip := range allIPs {
		ipSlice = append(ipSlice, ip)
	}

	if err := WriteToFile("subdomains.txt", subdomainSlice); err != nil {
		fmt.Printf("Error writing subdomains file: %v\n", err)
	} else {
		fmt.Printf("Subdomains written to subdomains.txt (%d entries)\n", len(subdomainSlice))
	}

	if err := WriteToFile("ips.txt", ipSlice); err != nil {
		fmt.Printf("Error writing IPs file: %v\n", err)
	} else {
		fmt.Printf("IPs written to ips.txt (%d entries)\n", len(ipSlice))
	}

	fmt.Println("All done!")
}
