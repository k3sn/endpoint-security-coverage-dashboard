# Endpoint Security Coverage Dashboard

A multi-tenant Microsoft Defender analytics dashboard built with Python and Streamlit.

The project combines Microsoft Defender Device Inventory exports from two tenants or operational regions with a Microsoft Defender Antivirus Health export. It converts separate CSV files into a single daily security health-check workflow with onboarding, endpoint health, operating-system, antivirus, telemetry, network-correlation, and investigation reports.

> This public portfolio edition uses generic terminology and synthetic sample data. It contains no employer, client, tenant, production hostname, production domain, live IPAM range, real device identifier, or real security export.

## Why This Project Exists

Microsoft Defender data can be spread across separate tenants and exports. Reviewing those exports manually makes it difficult to answer basic operational questions consistently, including:

- How many unique devices are visible across the environments?
- How many devices and servers are onboarded in each tenant?
- What percentage of the known estate is onboarded?
- Which devices appear eligible for onboarding?
- Which devices require manual investigation?
- Which unknown devices are using recognised corporate IP ranges?
- Which devices have stale inventory data?
- Which operating systems are present?
- Which devices are running legacy operating systems?
- Which devices have missing or invalid sensor telemetry?
- What is the Microsoft Defender Antivirus signature compliance rate?
- Which devices have outdated or unknown Defender signatures?
- Which devices have Defender engine, platform, telemetry, or scan issues?

The dashboard automates those checks and produces searchable, exportable device-level reports behind the headline metrics.

## Key Capabilities

### Multi-source CSV ingestion

The application accepts:

1. Device Inventory export for Region A
2. Device Inventory export for Region B
3. Microsoft Defender Antivirus Details export

The current implementation is designed for two Device Inventory sources. The same architecture can be extended to support additional tenants by expanding the loader, regional configuration, dashboard labels, and reporting loops.

### Automatic source classification

The two Device Inventory files can be uploaded in either order. The loader scores identifying tags, domains, and hostname prefixes to determine which regional dataset each export represents.

The public version uses synthetic Region A and Region B indicators. Production implementations should move these indicators into configuration rather than hard-code organisation-specific rules.

### Device deduplication

Many export rows can refer to the same endpoint. The analysis normalises device names, removes domain suffixes where appropriate, and selects the most complete record for reporting.

This prevents duplicate inventory rows from inflating unique-device metrics.

### Onboarding candidate analysis

The matching workflow evaluates devices marked as capable of onboarding and separates them into:

- Possible onboarding candidates
- Investigation required
- Already onboarded elsewhere
- Excluded candidates

Evidence can include:

- Official naming-rule matches
- Naming families observed among onboarded devices
- Meaningful generated naming families
- Repeated candidate naming families
- Recognised domains

### Naming-pattern discovery

The application learns structural patterns and naming families from devices already marked as onboarded.

Examples of generated concepts include:

- Alphabetic prefix followed by a numeric suffix
- Site, environment, role, and sequence-based server names
- Hyphenated workstation naming structures
- Repeated server-role families

The discovery stage creates separate structural-pattern and naming-family reports.

### Internal network correlation

Devices requiring investigation are checked against a reference IPAM dataset.

The network workflow:

- Extracts IPv4 addresses from the inventory data
- Rejects invalid, loopback, link-local, multicast, unspecified, and reserved values
- Ignores `192.168.0.0/16` because it is commonly reused on home and local networks
- Uses longest-prefix matching so the most specific matching CIDR is selected
- Returns network, location, VLAN, description, hierarchy, and review metadata

The result is an investigation list for unknown devices using recognised corporate network ranges.

### Onboarding coverage metrics

The dashboard reports:

- Total unique devices investigated
- Overall onboarding coverage percentage
- Region A devices onboarded
- Region B devices onboarded
- Region A servers onboarded
- Region B servers onboarded

Onboarding coverage is calculated as:

```text
Unique onboarded devices / total unique devices * 100
```

### Device health metrics

The application reports:

- Sensor-data issues by region
- Unsupported devices by region
- Devices stale for 31 to 60 days
- Devices stale for 61 to 90 days
- Devices stale for more than 90 days

The stale buckets are non-overlapping so each device appears in only one age category.

### Consolidated sensor-health analysis

Sensor-data issues are identified from both Device Inventory and Microsoft Defender Antivirus data.

The correlation order is:

1. Device ID
2. Normalised device name

Examples of conditions treated as telemetry issues include:

- Inventory values containing `No sensor data`
- AV mode reported as `Other`
- Missing AV mode
- Security intelligence version missing or reported as `0.0.0.0`
- Defender engine version missing or invalid
- Defender platform version missing or invalid

The output records the issue source, issue reason, match method, inventory data, and available Defender health context.

### Operating-system reporting

The dashboard groups unique devices into:

- Windows 11
- Windows 10
- Windows Server
- Linux
- macOS
- Mobile
- Other or unknown

The detailed OS inventory remains available as a CSV report.

### Legacy operating-system detection

Legacy OS classification is rule-based and intentionally kept in one editable function.

The included example rules cover:

- Windows XP
- Windows 7
- Windows 8 and 8.1
- Windows Server 2008 and 2008 R2
- Windows Server 2012 and 2012 R2
- Configured older Windows 10 releases

These rules are examples and should be reviewed against the organisation's approved lifecycle standard before operational use.

### Microsoft Defender Antivirus health

The Defender health module analyses:

- AV reporting devices
- Active AV mode
- Passive AV mode
- EDR blocked mode
- Other or unknown AV modes
- Security intelligence compliance
- Defender engine compliance
- Defender platform compliance
- Latest observed security intelligence version
- Latest observed engine version
- Latest observed platform version
- Quick scan status
- Full scan status
- Missing or invalid Defender telemetry

### Signature compliance

Signature compliance uses the explicit `Security intelligence up to date` value in the uploaded Defender report.

Devices are classified as:

- `COMPLIANT`
- `NON-COMPLIANT`
- `UNKNOWN`

The percentage is calculated as:

```text
Compliant / (Compliant + Non-compliant) * 100
```

Unknown devices are excluded from the compliance denominator and reported separately. This prevents missing telemetry from being presented as either compliant or confirmed non-compliant.

The highest observed security intelligence, engine, and platform versions are displayed for context only. They are not used by themselves to determine compliance.

### Actionable reports

Every major dashboard issue has a device-level CSV behind it. Users can select a report, search across all columns, inspect the data in a scrollable table, and export the currently displayed rows.

If a search filter is active, the export contains only the filtered rows.

## Project Structure

```text
endpoint-security-coverage-dashboard/
|
|-- app.py
|-- config.py
|-- loader.py
|-- naming_rules.py
|-- pattern_discovery.py
|-- matching.py
|-- internal_network.py
|-- onboarded_devices.py
|-- device_metrics.py
|-- defender_health.py
|-- main.py
|
|-- reference/
|   |-- sample_naming_rules.csv
|   `-- sample_ipam.csv
|
|-- sample_data/
|   |-- region_a_devices.csv
|   |-- region_b_devices.csv
|   `-- antivirus_health.csv
|
|-- output/
|   `-- .gitkeep
|
|-- requirements.txt
|-- .gitignore
`-- README.md
```

## File-by-File Explanation

### `app.py`

The Streamlit presentation and orchestration layer.

Responsibilities:

- Configures the page and dashboard layout
- Displays three CSV upload controls
- Runs the complete analysis pipeline
- Stores results in Streamlit session state
- Displays grouped dashboard metrics with hover descriptions
- Loads generated CSV reports into pandas DataFrames
- Provides a report selector
- Searches across every visible report column
- Displays a scrollable table
- Exports the selected or filtered report
- Clears the current analysis session

Heavy analysis modules are imported inside the analysis function so the initial interface can render before the processing pipeline is executed.

### `config.py`

Central path configuration.

It defines:

- Project base directory
- Input directory
- Output directory
- Reference-data directory

Using paths relative to the project directory avoids hard-coded user or workstation paths.

### `loader.py`

The ingestion and raw-data preparation layer.

Responsibilities:

- Reads physical CSV files for command-line execution
- Reads Streamlit uploaded files from memory
- Handles UTF-8 with BOM and a Windows encoding fallback
- Cleans headers and values
- Validates that the two Device Inventory exports use matching columns
- Prevents the same upload from being used twice
- Detects Region A and Region B from configurable-style data indicators
- Saves separate regional raw datasets
- Saves a combined raw dataset
- Saves the Antivirus Health export separately

Generated raw outputs:

```text
combined_raw_dataset.csv
region_a_raw_dataset.csv
region_b_raw_dataset.csv
mdav_raw_dataset.csv
```

The Antivirus Health data is kept separate because its schema and purpose differ from the Device Inventory schema.

### `naming_rules.py`

Loads and validates official naming rules from the reference CSV.

Responsibilities:

- Reads enabled naming rules
- Builds sets of site, environment, role, and type codes
- Loads official regular-expression formats
- Validates workstation names
- Validates supported server-name structures
- Returns structured match details and human-readable validation reasons

Keeping naming standards in a CSV allows rules to be changed without rewriting the entire matching engine.

### `pattern_discovery.py`

Discovers naming structures from known onboarded devices.

Responsibilities:

- Normalises device names, onboarding status, and device type
- Removes domain suffixes
- Excludes GUIDs, long hexadecimal identifiers, and configured name groups
- Creates structural patterns such as alphabetic and numeric layouts
- Creates broader naming families
- Separates server and workstation family logic
- Writes naming-pattern and naming-family reports

Only onboarded devices are permitted to teach the discovery engine. This prevents unverified candidates from defining the expected naming standard.

### `matching.py`

The onboarding-candidate decision engine.

Responsibilities:

- Builds an index of onboarded hostnames
- Builds domains observed among onboarded devices
- Builds naming families observed among onboarded devices
- Builds repeated candidate-family evidence
- Checks whether a candidate is already onboarded elsewhere
- Applies explicit exclusions
- Evaluates official naming standards
- Evaluates generated naming-family evidence
- Evaluates recognised-domain evidence
- Produces a human-readable candidate reason
- Writes separate result reports

Primary classifications:

```text
POSSIBLE ONBOARDING CANDIDATE
INVESTIGATION REQUIRED
ALREADY ONBOARDED
EXCLUDED
```

The matching logic is evidence-based rather than a machine-learning model. Each classification includes the evidence used to reach it.

### `internal_network.py`

Correlates investigation-required devices with the reference IPAM dataset.

Responsibilities:

- Loads IPv4 CIDR references
- Filters unusable or ambiguous ranges
- Extracts candidate IPv4 addresses from text fields
- Validates addresses
- Applies longest-prefix matching
- Prevents devices with existing naming evidence from being reclassified by the network stage
- Writes an internal-network investigation report

This stage is intended to identify devices that lack sufficient naming evidence but are visible on recognised corporate networks.

### `onboarded_devices.py`

Calculates regional onboarding counts.

Responsibilities:

- Loads the separate regional raw datasets
- Filters devices with `Onboarding Status = Onboarded`
- Deduplicates by normalised device name
- Detects servers from Device Type or Device Category
- Returns device and server onboarding totals for both regions

This module stays deliberately small because its purpose is to provide stable, understandable coverage metrics.

### `device_metrics.py`

Calculates general inventory, device-health, sensor, staleness, OS, and legacy metrics.

Responsibilities:

- Loads Region A, Region B, and optional Antivirus Health data
- Deduplicates inventory devices
- Calculates the overall onboarding percentage
- Counts unsupported devices by region
- Calculates non-overlapping stale-device buckets
- Classifies operating systems
- Detects configured legacy OS versions
- Correlates inventory and Defender health records
- Produces a consolidated no-sensor-data report
- Writes actionable CSV reports

This module correlates Antivirus Health to Device Inventory by Device ID first, then by normalised device name.

### `defender_health.py`

Analyses Microsoft Defender Antivirus health independently of the general device metrics.

Responsibilities:

- Loads and deduplicates the Defender Antivirus dataset
- Counts AV mode states
- Classifies signature, engine, and platform compliance
- Calculates compliance percentages
- Finds the latest observed component versions
- Classifies quick and full scan status
- Detects telemetry issues
- Writes full health and exception reports

Keeping this logic separate prevents antivirus-specific rules from being mixed into the general asset-inventory analysis.

### `main.py`

Provides the original command-line entry point for the core onboarding workflow.

The Streamlit application is the primary portfolio interface. `main.py` remains useful for running the core loader, naming discovery, matching, and internal-network stages without the web interface.

## Analysis Pipeline

```text
Three uploaded CSV files
        |
        v
loader.py
        |
        |-- Region A raw dataset
        |-- Region B raw dataset
        |-- Combined raw dataset
        `-- Antivirus health raw dataset
        |
        v
Naming rules + pattern discovery
        |
        v
Onboarding candidate matching
        |
        v
Internal network correlation
        |
        |-- Regional onboarding metrics
        |-- Device health and OS metrics
        `-- Defender Antivirus health metrics
        |
        v
Streamlit dashboard
        |
        `-- Searchable and exportable CSV reports
```

## Generated Reports

Depending on the data, the application can generate:

### Onboarding and investigation

```text
possible_onboarding_candidates.csv
investigation_required.csv
already_onboarded_devices.csv
excluded_onboarding_candidates.csv
internal_ip_investigate.csv
```

### Naming discovery

```text
discovered_naming_families.csv
discovered_naming_patterns.csv
```

### Device health and operating systems

```text
no_sensor_data.csv
unsupported_devices.csv
stale_devices.csv
operating_system_inventory.csv
legacy_os_devices.csv
```

### Defender Antivirus health

```text
defender_av_health.csv
defender_signature_non_compliant.csv
defender_signature_unknown.csv
defender_signature_attention_required.csv
defender_update_issues.csv
defender_telemetry_issues.csv
defender_scan_issues.csv
```

### Prepared raw data

```text
region_a_raw_dataset.csv
region_b_raw_dataset.csv
combined_raw_dataset.csv
mdav_raw_dataset.csv
```

## Design Decisions

### Why CSV exports?

CSV files make the project portable and easy to demonstrate without requiring tenant API credentials, Microsoft Graph permissions, application registration, or cloud infrastructure.

### Why Streamlit?

Streamlit provides a lightweight local interface for file upload, dashboard metrics, searchable tables, and report downloads without requiring a separate frontend and backend application.

### Why keep the raw datasets separate?

The two Device Inventory datasets have the same schema and can be combined. The Antivirus Health dataset has a different schema, so it is retained separately and correlated only where required.

### Why use Device ID before device name?

Device ID is the stronger available correlation key. Normalised device name is used only as a fallback because names can differ between short-hostname and fully qualified forms.

### Why remove the domain suffix?

One export can report a short hostname while another reports a fully qualified domain name. Removing the suffix improves cross-report matching while preserving the original name in the detailed output.

### Why deduplicate?

Security inventories can contain multiple records for the same endpoint. Headline metrics should represent unique devices rather than raw export rows.

### Why exclude unknown signature status from the compliance rate?

An unknown status is not proof of compliance or non-compliance. Unknown telemetry is displayed separately so the compliance percentage reflects devices with an explicit Yes or No update status.

### Why use the report's compliance fields instead of version distance?

Version-number distance alone does not reliably express whether a device meets the configured update policy. The dashboard uses the explicit update-status fields for compliance and displays observed versions separately for context.

### Why use non-overlapping stale buckets?

Non-overlapping ranges prevent one endpoint from being counted in multiple stale categories and make the dashboard totals easier to interpret.

### Why ignore `192.168.0.0/16` in IP correlation?

That range is commonly used outside corporate networks. Treating it as strong corporate-network evidence could create false positives.

### Why use longest-prefix matching?

An IP can match multiple reference networks. Selecting the most specific CIDR returns the most precise available network context.

### Why is the analysis rule-based?

The project is intended to produce explainable operational reports. The output records the exact naming, domain, status, network, or telemetry evidence behind each decision.

### Why synthetic data only?

Endpoint security exports can contain sensitive hostnames, domains, addresses, device identifiers, architecture details, and health information. The public repository therefore includes only synthetic examples created for demonstration.

## Installation

### Prerequisites

- Python 3.10 or later recommended
- `pip`
- A local terminal or PowerShell session

### Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```bat
python -m venv .venv
.venv\Scripts\activate.bat
```

macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

## Running the Dashboard

```bash
python -m streamlit run app.py
```

Streamlit will display the local application address in the terminal.

## Using the Application

1. Open the Streamlit interface.
2. Upload the Region A Device Inventory sample.
3. Upload the Region B Device Inventory sample.
4. Upload the Microsoft Defender Antivirus Health sample.
5. Select **Run Analysis**.
6. Review the dashboard sections.
7. Select a detailed report in the Report Viewer.
8. Search across any field if required.
9. Export the complete or filtered report as CSV.

For the included demonstration, use:

```text
sample_data/region_a_devices.csv
sample_data/region_b_devices.csv
sample_data/antivirus_health.csv
```

## Expected Input Concepts

The application expects Device Inventory exports to contain fields representing concepts such as:

```text
Device ID
Device Name
Device Category
Device Type
Onboarding Status
OS Platform
OS Version
Domain
Device IPs
Managed By
Group
Last Device Update
Tags
```

The Antivirus Health export expects concepts such as:

```text
Device ID
Device name
Device group
OS
OS platform
OS version
AV mode
Security intel version
Engine version
Platform version
Quick scan status
Full scan status
Last seen
Security intelligence up to date
Engine up to date
Platform up to date
```

Column names must match the constants currently defined in the source files. A production enhancement would add a schema-mapping layer for exports with different labels.

## Configuration and Customisation

### Add more tenants

To support more than two Device Inventory sources:

1. Change the upload interface to accept additional files or multiple files.
2. Replace two-source detection with a configurable source list.
3. Save each classified source using a generated filename.
4. Loop through regional metrics instead of using two fixed keys.
5. Render dashboard cards dynamically.

### Change source-classification rules

Update the detection logic in `loader.py`, or move the indicators into a configuration file.

Recommended configurable indicators include:

- Tag values
- Domain suffixes
- Hostname prefixes
- Tenant-specific groups

### Change official naming rules

Edit:

```text
reference/sample_naming_rules.csv
```

Each enabled rule can define its category, type, scope, pattern, format, and relevant site, role, environment, or device-type code.

### Change network references

Edit:

```text
reference/sample_ipam.csv
```

The reference supports:

```text
NetworkCIDR
DisplayName
Description
Location
VLAN
Section
Hierarchy
ReviewFlag
```

### Change legacy OS rules

Edit `get_legacy_os_reason()` in `device_metrics.py`.

Only versions explicitly agreed by the organisation should be classified as legacy in an operational deployment.

### Change exclusions

Edit the configured exclusion list in `pattern_discovery.py`.

Exclusions should be used for identifiers or device families that should not influence naming discovery or onboarding recommendations.

## Security and Privacy

### Local processing

The project is intended to run locally. Uploaded files are processed by the local Streamlit process and derived reports are written to the local `output` directory.

### Do not commit real exports

The `.gitignore` excludes common input and output locations, but users should still inspect staged files before every commit.

Useful checks include:

```bash
git status
git diff --cached
```

Never publish:

- Real endpoint inventories
- Antivirus health exports
- Hostnames
- Device IDs
- Tenant identifiers
- Usernames or email addresses
- Internal domains
- IPAM exports
- Network ranges
- Vulnerability details
- Screenshots containing production information
- Credentials, tokens, certificates, or secrets

### Repository-history warning

Do not initialise the public repository inside a directory that previously contained sensitive data. Create a new clean directory and a new Git history for the portfolio edition.

## Known Limitations

- The current UI accepts exactly two Device Inventory files.
- Source classification depends on configured indicators.
- Input schemas must match the expected column names.
- CSV processing is local and does not pull data directly from Microsoft APIs.
- The latest observed Defender versions come from the uploaded report, not an external authoritative version feed.
- Naming-family discovery is heuristic and should support, not replace, human review.
- IP correlation is only as accurate as the reference IPAM data.
- Legacy OS decisions require organisation-specific lifecycle rules.
- Device-name fallback matching can be ambiguous if the same short hostname exists in multiple domains.
- A CSV report represents a point-in-time export rather than continuous monitoring.

## Possible Future Enhancements

- Dynamic support for any number of tenants
- Config-driven tenant detection
- Column/schema mapping
- Direct Microsoft Graph or Defender API ingestion
- Authentication and role-based access
- Historical trend storage
- Scheduled report generation
- Coverage trends over time
- Configurable compliance thresholds
- Configurable stale-device buckets
- External current-version comparison
- Interactive charts
- Unit and integration tests
- Structured logging
- Packaging as a container
- CI checks for secrets and sensitive strings

## Testing Strategy

A production-ready implementation should include tests for:

- CSV decoding and malformed rows
- Header validation
- Duplicate-device selection
- Source classification
- Hostname normalisation
- Naming-family generation
- Official naming-rule validation
- Candidate classification
- IPv4 extraction and validation
- Longest-prefix CIDR matching
- Stale date boundaries
- OS categorisation
- Legacy OS rules
- Device ID and hostname correlation
- Signature compliance calculations
- Unknown telemetry handling
- Empty-report generation

The included synthetic files are intended as functional demonstration data, not as a complete automated test suite.

## Technology Stack

- Python
- Streamlit
- pandas
- Python standard-library CSV processing
- Python `ipaddress` for CIDR analysis
- Regular expressions for naming and version parsing

## Portfolio Context

This repository demonstrates practical security-engineering skills, including:

- Endpoint security operations
- Multi-source data correlation
- Microsoft Defender reporting concepts
- Explainable rule-based analytics
- Asset onboarding analysis
- Antivirus compliance reporting
- Network and IPAM correlation
- Data cleansing and deduplication
- Security dashboard design
- Actionable CSV report generation

## Disclaimer

This project is provided as a portfolio demonstration and reference implementation. It is not an official Microsoft product and is not affiliated with or endorsed by Microsoft.

All included data is synthetic. Before adapting the project for a real environment, review applicable security, privacy, employment, intellectual-property, open-source, and client-confidentiality requirements.

The classifications produced by the tool are operational indicators and should be validated by authorised security personnel before remediation or business decisions are made.

## License

No license is granted automatically merely by publishing source code. Add an explicit license only after confirming that the repository can be publicly distributed and deciding the permissions that should apply.
