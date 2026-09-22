# Endpoint Security Coverage Dashboard

A portfolio-safe demonstration of a Python and Streamlit security analytics workflow for correlating endpoint inventory, naming conventions, network ranges, and antivirus health data.

## Features
- Multi-source CSV ingestion and device deduplication
- Synthetic Region A / Region B classification
- Naming-pattern and naming-family discovery
- Rule-based onboarding-candidate analysis
- IPv4/CIDR reference matching
- Stale, unsupported, sensor-health, OS and legacy-OS reporting
- Antivirus signature, engine, platform, telemetry and scan health reporting
- Interactive Streamlit dashboard with searchable CSV exports

## Demo data
All data under `sample_data/` and `reference/` is synthetic and provided only to demonstrate the application structure. No employer, client, production hostname, production domain, production IPAM, tenant identifier, or real endpoint export is included.

## Run
1. Create a virtual environment.
2. Install `requirements.txt`.
3. Run `python -m streamlit run app.py`.
4. Upload the two synthetic regional device inventories and the synthetic antivirus-health CSV.

## Important
This repository is a generic portfolio reimplementation. Review applicable employment, intellectual-property, confidentiality, and open-source policies before publishing any work-derived implementation.
