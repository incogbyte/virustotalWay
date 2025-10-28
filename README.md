# VirusTotal Way

A Go program that fetches domain information from VirusTotal API and generates separate files containing subdomains and IP addresses.

## Features

- API key rotation between multiple VirusTotal API keys
- Rate limiting with 20-second delays between requests
- Domain processing for single domains or files with multiple domains
- Data extraction from multiple sources (subdomains, DNS resolutions, undetected URLs)
- Output files: `subdomains.txt` and `ips.txt`
- API key testing functionality

## Prerequisites

- Go 1.21 or later
- Valid VirusTotal API keys

## Installation

1. Clone or download the project
2. Replace the API keys in `main.go` with your actual VirusTotal API keys:

```go
apiKeys := []string{
    "your-first-api-key",
    "your-second-api-key", 
    "your-third-api-key",
}
```

## Usage

### Test API Keys

Before running the main program, test your API keys:

```bash
go run main.go --test
```

This will test all configured API keys and show their status.

### Single Domain

Process a single domain:

```bash
go run main.go example.com
```

### Multiple Domains from File

Create a text file with one domain per line:

```
example.com
google.com
github.com
```

Then run:

```bash
go run main.go domains.txt
```

## Output Files

The program generates two files:

- `subdomains.txt` - Contains all unique subdomains found
- `ips.txt` - Contains all unique IP addresses found

## API Key Configuration

Edit the `apiKeys` slice in `main.go`:

```go
apiKeys := []string{
    "your-first-api-key",
    "your-second-api-key", 
    "your-third-api-key",
}
```

## Rate Limiting

The program implements rate limiting:
- 20-second delay between requests
- API key rotation every 5 requests
- Proper error handling for failed requests

## Error Handling

The program handles various error conditions:
- Network connectivity issues
- Invalid API responses
- File I/O operations
- JSON parsing errors

## Example Output

```
Testing API keys...
Testing API key 1: 1323e3c1...
API key 1 working correctly
Testing API key 2: e362a563...
API key 2 working correctly
API key testing completed.

Processing domain 1/1: example.com

Fetching data for domain: example.com (using API key 1)
Found 5 subdomains and 3 IPs for example.com
Subdomains written to subdomains.txt (5 entries)
IPs written to ips.txt (3 entries)
All done!
```
