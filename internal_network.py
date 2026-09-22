import csv
import ipaddress
import re

from config import OUTPUT_DIR
from config import REFERENCE_DIR


# --------------------------------------------------
# Files
# --------------------------------------------------

IPAM_REFERENCE_FILE = (
    REFERENCE_DIR
    / "sample_ipam.csv"
)

INTERNAL_IP_OUTPUT = (
    OUTPUT_DIR
    / "internal_ip_investigate.csv"
)


# --------------------------------------------------
# Column names
# --------------------------------------------------

DEVICE_ID_COLUMN = "Device ID"
DEVICE_NAME_COLUMN = "Original Device Name"
NORMALISED_NAME_COLUMN = "Normalised Device Name"
DEVICE_CATEGORY_COLUMN = "Device Category"
DEVICE_TYPE_COLUMN = "Device Type"
ONBOARDING_STATUS_COLUMN = "Onboarding Status"

NAMING_FAMILY_COLUMN = "Generated Naming Family"
MEANINGFUL_FAMILY_COLUMN = "Meaningful Naming Family"

OFFICIAL_MATCH_COLUMN = "Official Naming Match"
ONBOARDED_FAMILY_MATCH_COLUMN = "Onboarded Family Match"
CANDIDATE_FAMILY_MATCH_COLUMN = "Candidate Family Match"

DOMAIN_COLUMN = "Domain"
DEVICE_IPS_COLUMN = "Device IPs"

OS_PLATFORM_COLUMN = "OS Platform"
OS_VERSION_COLUMN = "OS Version"

AAD_DEVICE_ID_COLUMN = "AAD Device Id"
MANAGED_BY_COLUMN = "Managed By"
GROUP_COLUMN = "Group"
LAST_UPDATE_COLUMN = "Last Device Update"

CLASSIFICATION_COLUMN = "Final Classification"


# --------------------------------------------------
# IPAM columns
# --------------------------------------------------

IPAM_NETWORK_COLUMN = "NetworkCIDR"
IPAM_DISPLAY_NAME_COLUMN = "DisplayName"
IPAM_DESCRIPTION_COLUMN = "Description"
IPAM_LOCATION_COLUMN = "Location"
IPAM_VLAN_COLUMN = "VLAN"
IPAM_SECTION_COLUMN = "Section"
IPAM_HIERARCHY_COLUMN = "Hierarchy"
IPAM_REVIEW_FLAG_COLUMN = "ReviewFlag"


# --------------------------------------------------
# Basic helpers
# --------------------------------------------------

def clean_value(value):

    if value is None:
        return ""

    return str(value).strip()


def value_is_true(value):

    if isinstance(value, bool):
        return value

    return (
        clean_value(value).lower()
        == "true"
    )


# --------------------------------------------------
# Remove 192.168.x.x addresses
#
# These addresses are commonly reused on home
# networks and are too ambiguous for this report.
# --------------------------------------------------

def is_ambiguous_home_range(
    ip_object
):

    home_network = ipaddress.ip_network(
        "192.168.0.0/16"
    )

    return ip_object in home_network


# --------------------------------------------------
# Load IPAM reference
# --------------------------------------------------

def load_ipam_reference():

    if not IPAM_REFERENCE_FILE.exists():

        raise FileNotFoundError(
            f"IPAM reference file not found: "
            f"{IPAM_REFERENCE_FILE}"
        )


    ipam_networks = []

    ignored_192168_networks = 0

    invalid_networks = 0


    with open(
        IPAM_REFERENCE_FILE,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(
            file,
            skipinitialspace=True
        )


        if not reader.fieldnames:

            raise ValueError(
                "IPAM reference file has no headers."
            )


        for raw_row in reader:

            row = {}


            for key, value in raw_row.items():

                if key is None:
                    continue

                row[
                    clean_value(key)
                ] = clean_value(value)


            network_cidr = row.get(
                IPAM_NETWORK_COLUMN,
                ""
            )


            if not network_cidr:
                continue


            try:

                network = ipaddress.ip_network(
                    network_cidr,
                    strict=False
                )

            except ValueError:

                invalid_networks += 1

                continue


            if network.version != 4:
                continue


            # Do not load any 192.168.x.x network
            if network.overlaps(
                ipaddress.ip_network(
                    "192.168.0.0/16"
                )
            ):

                ignored_192168_networks += 1

                continue


            row["_network"] = network

            ipam_networks.append(
                row
            )


    if not ipam_networks:

        raise ValueError(
            "No usable IPv4 networks were loaded "
            "from the IPAM reference file."
        )


    # Most specific CIDR first.
    #
    # For example, /24 is checked before /16.
    ipam_networks.sort(
        key=lambda row:
            row["_network"].prefixlen,
        reverse=True
    )


    return {

        "networks":
            ipam_networks,

        "ignored_192168_networks":
            ignored_192168_networks,

        "invalid_networks":
            invalid_networks
    }


# --------------------------------------------------
# Extract IPv4-looking values
# --------------------------------------------------

def extract_ipv4_candidates(
    device_ips
):

    value = clean_value(
        device_ips
    )


    if not value:
        return []


    return re.findall(
        r"(?<![0-9])"
        r"(?:"
        r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
        r"\."
        r"){3}"
        r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
        r"(?![0-9])",
        value
    )


# --------------------------------------------------
# Validate a device IPv4 address
# --------------------------------------------------

def is_valid_device_ipv4(
    ip_address
):

    try:

        ip_object = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return False


    if ip_object.version != 4:
        return False


    if ip_object.is_loopback:
        return False


    if ip_object.is_link_local:
        return False


    if ip_object.is_multicast:
        return False


    if ip_object.is_unspecified:
        return False


    if ip_object.is_reserved:
        return False


    if str(ip_object) == "255.255.255.255":
        return False


    # Critical home-network safeguard
    if is_ambiguous_home_range(
        ip_object
    ):

        return False


    return True


# --------------------------------------------------
# Extract every unique valid IPv4 address
#
# Order from Defender is preserved.
# --------------------------------------------------

def extract_valid_ipv4_addresses(
    device_ips
):

    valid_addresses = []

    seen_addresses = set()


    candidates = extract_ipv4_candidates(
        device_ips
    )


    for candidate in candidates:

        if not is_valid_device_ipv4(
            candidate
        ):

            continue


        if candidate in seen_addresses:
            continue


        seen_addresses.add(
            candidate
        )

        valid_addresses.append(
            candidate
        )


    return valid_addresses


# --------------------------------------------------
# Find the most specific IPAM match
# --------------------------------------------------

def find_ipam_match(
    ip_address,
    ipam_networks
):

    try:

        ip_object = ipaddress.ip_address(
            ip_address
        )

    except ValueError:

        return None


    if is_ambiguous_home_range(
        ip_object
    ):

        return None


    for ipam_row in ipam_networks:

        network = ipam_row[
            "_network"
        ]


        if ip_object in network:

            return ipam_row


    return None


# --------------------------------------------------
# Protect against named candidates being passed
# into the internal-network stage
# --------------------------------------------------

def has_naming_evidence(
    record
):

    official_match = value_is_true(
        record.get(
            OFFICIAL_MATCH_COLUMN,
            False
        )
    )


    onboarded_family_match = value_is_true(
        record.get(
            ONBOARDED_FAMILY_MATCH_COLUMN,
            False
        )
    )


    meaningful_family = value_is_true(
        record.get(
            MEANINGFUL_FAMILY_COLUMN,
            False
        )
    )


    candidate_family_match = value_is_true(
        record.get(
            CANDIDATE_FAMILY_MATCH_COLUMN,
            False
        )
    )


    return (
        official_match
        or onboarded_family_match
        or meaningful_family
        or candidate_family_match
    )


# --------------------------------------------------
# Build output row
# --------------------------------------------------

def create_internal_match_output(
    record,
    valid_ipv4_addresses,
    matched_ip,
    ipam_match
):

    network = ipam_match[
        "_network"
    ]


    review_flag = clean_value(
        ipam_match.get(
            IPAM_REVIEW_FLAG_COLUMN,
            ""
        )
    )


    if review_flag:

        reason = (
            "No qualifying naming evidence, but "
            "the device IP matches a CORP IPAM "
            f"network flagged {review_flag}"
        )

    else:

        reason = (
            "No qualifying naming evidence, but "
            "the device IP matches a known "
            "internal CORP IPAM network"
        )


    return {

        "Device ID":
            record.get(
                DEVICE_ID_COLUMN,
                ""
            ),

        "Original Device Name":
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            ),

        "Normalised Device Name":
            record.get(
                NORMALISED_NAME_COLUMN,
                ""
            ),

        "Device Category":
            record.get(
                DEVICE_CATEGORY_COLUMN,
                ""
            ),

        "Device Type":
            record.get(
                DEVICE_TYPE_COLUMN,
                ""
            ),

        "Onboarding Status":
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            ),

        "Previous Classification":
            record.get(
                CLASSIFICATION_COLUMN,
                ""
            ),

        "Generated Naming Family":
            record.get(
                NAMING_FAMILY_COLUMN,
                ""
            ),

        "Meaningful Naming Family":
            record.get(
                MEANINGFUL_FAMILY_COLUMN,
                ""
            ),

        "Official Naming Match":
            record.get(
                OFFICIAL_MATCH_COLUMN,
                ""
            ),

        "Onboarded Family Match":
            record.get(
                ONBOARDED_FAMILY_MATCH_COLUMN,
                ""
            ),

        "Candidate Family Match":
            record.get(
                CANDIDATE_FAMILY_MATCH_COLUMN,
                ""
            ),

        "Domain":
            record.get(
                DOMAIN_COLUMN,
                ""
            ),

        "Original Device IPs":
            record.get(
                DEVICE_IPS_COLUMN,
                ""
            ),

        "Valid IPv4 Addresses":
            ", ".join(
                valid_ipv4_addresses
            ),

        "Matched Internal IP":
            matched_ip,

        "Matched Network CIDR":
            str(network),

        "Matched Prefix Length":
            network.prefixlen,

        "IPAM Display Name":
            ipam_match.get(
                IPAM_DISPLAY_NAME_COLUMN,
                ""
            ),

        "IPAM Description":
            ipam_match.get(
                IPAM_DESCRIPTION_COLUMN,
                ""
            ),

        "IPAM Location":
            ipam_match.get(
                IPAM_LOCATION_COLUMN,
                ""
            ),

        "IPAM VLAN":
            ipam_match.get(
                IPAM_VLAN_COLUMN,
                ""
            ),

        "IPAM Section":
            ipam_match.get(
                IPAM_SECTION_COLUMN,
                ""
            ),

        "IPAM Hierarchy":
            ipam_match.get(
                IPAM_HIERARCHY_COLUMN,
                ""
            ),

        "IPAM Review Flag":
            review_flag,

        "OS Platform":
            record.get(
                OS_PLATFORM_COLUMN,
                ""
            ),

        "OS Version":
            record.get(
                OS_VERSION_COLUMN,
                ""
            ),

        "AAD Device Id":
            record.get(
                AAD_DEVICE_ID_COLUMN,
                ""
            ),

        "Managed By":
            record.get(
                MANAGED_BY_COLUMN,
                ""
            ),

        "Group":
            record.get(
                GROUP_COLUMN,
                ""
            ),

        "Last Device Update":
            record.get(
                LAST_UPDATE_COLUMN,
                ""
            ),

        "Reason":
            reason,

        "Final Classification":
            "INTERNAL IP INVESTIGATE"
    }


# --------------------------------------------------
# Analyse investigation-required records
# --------------------------------------------------

def analyse_internal_network(
    investigation_records,
    ipam_networks
):

    internal_matches = []


    devices_analysed = 0

    records_with_valid_ipv4 = 0

    records_with_only_ignored_ips = 0

    devices_without_internal_match = 0

    devices_skipped_naming_evidence = 0

    matched_device_keys = set()


    for record in investigation_records:

        devices_analysed += 1


        if has_naming_evidence(
            record
        ):

            devices_skipped_naming_evidence += 1

            continue


        original_device_ips = record.get(
            DEVICE_IPS_COLUMN,
            ""
        )


        all_ipv4_candidates = (
            extract_ipv4_candidates(
                original_device_ips
            )
        )


        valid_ipv4_addresses = (
            extract_valid_ipv4_addresses(
                original_device_ips
            )
        )


        if not valid_ipv4_addresses:

            if all_ipv4_candidates:

                records_with_only_ignored_ips += 1


            devices_without_internal_match += 1

            continue


        records_with_valid_ipv4 += 1

        device_had_match = False


        # Check every valid IPv4 address
        for ip_address in valid_ipv4_addresses:

            ipam_match = find_ipam_match(
                ip_address,
                ipam_networks
            )


            if not ipam_match:
                continue


            device_had_match = True


            internal_matches.append(
                create_internal_match_output(
                    record,
                    valid_ipv4_addresses,
                    ip_address,
                    ipam_match
                )
            )


        if device_had_match:

            device_key = clean_value(
                record.get(
                    NORMALISED_NAME_COLUMN,
                    ""
                )
            )


            if not device_key:

                device_key = clean_value(
                    record.get(
                        DEVICE_ID_COLUMN,
                        ""
                    )
                )


            matched_device_keys.add(
                device_key
            )


        else:

            devices_without_internal_match += 1


    return {

        "internal_matches":
            internal_matches,

        "devices_analysed":
            devices_analysed,

        "records_with_valid_ipv4":
            records_with_valid_ipv4,

        "records_with_only_ignored_ips":
            records_with_only_ignored_ips,

        "devices_with_internal_match":
            len(
                matched_device_keys
            ),

        "devices_without_internal_match":
            devices_without_internal_match,

        "devices_skipped_naming_evidence":
            devices_skipped_naming_evidence
    }


# --------------------------------------------------
# Output columns
# --------------------------------------------------

def get_output_fields():

    return [

        "Device ID",

        "Original Device Name",

        "Normalised Device Name",

        "Device Category",

        "Device Type",

        "Onboarding Status",

        "Previous Classification",

        "Generated Naming Family",

        "Meaningful Naming Family",

        "Official Naming Match",

        "Onboarded Family Match",

        "Candidate Family Match",

        "Domain",

        "Original Device IPs",

        "Valid IPv4 Addresses",

        "Matched Internal IP",

        "Matched Network CIDR",

        "Matched Prefix Length",

        "IPAM Display Name",

        "IPAM Description",

        "IPAM Location",

        "IPAM VLAN",

        "IPAM Section",

        "IPAM Hierarchy",

        "IPAM Review Flag",

        "OS Platform",

        "OS Version",

        "AAD Device Id",

        "Managed By",

        "Group",

        "Last Device Update",

        "Reason",

        "Final Classification"
    ]


# --------------------------------------------------
# Write CSV
# --------------------------------------------------

def write_internal_ip_report(
    records
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    with open(
        INTERNAL_IP_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=get_output_fields()
        )


        writer.writeheader()


        sorted_records = sorted(
            records,
            key=lambda row: (

                row.get(
                    "Normalised Device Name",
                    ""
                ),

                -int(
                    row.get(
                        "Matched Prefix Length",
                        0
                    )
                ),

                row.get(
                    "Matched Internal IP",
                    ""
                )
            )
        )


        writer.writerows(
            sorted_records
        )


# --------------------------------------------------
# Main function
# --------------------------------------------------

def run_internal_network(
    investigation_records
):

    print()

    print(
        "Starting internal network investigation..."
    )


    ipam_results = load_ipam_reference()

    ipam_networks = ipam_results[
        "networks"
    ]


    results = analyse_internal_network(
        investigation_records,
        ipam_networks
    )


    write_internal_ip_report(
        results[
            "internal_matches"
        ]
    )


    print()

    print(
        "Internal network investigation completed."
    )

    print()

    print(
        f"IPAM networks loaded: "
        f"{len(ipam_networks)}"
    )

    print(
        f"192.168 IPAM networks ignored: "
        f"{ipam_results['ignored_192168_networks']}"
    )

    print(
        f"Invalid IPAM networks ignored: "
        f"{ipam_results['invalid_networks']}"
    )

    print()

    print(
        f"Investigation-required records analysed: "
        f"{results['devices_analysed']}"
    )

    print(
        f"Records with usable IPv4 addresses: "
        f"{results['records_with_valid_ipv4']}"
    )

    print(
        f"Records containing only ignored IPs: "
        f"{results['records_with_only_ignored_ips']}"
    )

    print(
        f"Unique devices matching internal IPAM: "
        f"{results['devices_with_internal_match']}"
    )

    print(
        f"Internal IP match rows written: "
        f"{len(results['internal_matches'])}"
    )

    print(
        f"Records without internal IP match: "
        f"{results['devices_without_internal_match']}"
    )

    print(
        f"Records skipped because naming evidence existed: "
        f"{results['devices_skipped_naming_evidence']}"
    )

    print()

    print(
        f"Internal IP investigation report: "
        f"{INTERNAL_IP_OUTPUT}"
    )


    return results