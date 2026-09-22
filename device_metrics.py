import csv
from datetime import datetime, timezone

from config import OUTPUT_DIR


Region A_RAW_DATASET = (
    OUTPUT_DIR
    / "region_a_raw_dataset.csv"
)

Region B_RAW_DATASET = (
    OUTPUT_DIR
    / "region_b_raw_dataset.csv"
)

MDAV_RAW_DATASET = (
    OUTPUT_DIR
    / "mdav_raw_dataset.csv"
)


STALE_OUTPUT = (
    OUTPUT_DIR
    / "stale_devices.csv"
)

UNSUPPORTED_OUTPUT = (
    OUTPUT_DIR
    / "unsupported_devices.csv"
)

NO_SENSOR_OUTPUT = (
    OUTPUT_DIR
    / "no_sensor_data.csv"
)

OS_INVENTORY_OUTPUT = (
    OUTPUT_DIR
    / "operating_system_inventory.csv"
)

LEGACY_OS_OUTPUT = (
    OUTPUT_DIR
    / "legacy_os_devices.csv"
)


DEVICE_NAME_COLUMN = "Device Name"
DEVICE_ID_COLUMN = "Device ID"

ONBOARDING_STATUS_COLUMN = (
    "Onboarding Status"
)

DEVICE_TYPE_COLUMN = (
    "Device Type"
)

DEVICE_CATEGORY_COLUMN = (
    "Device Category"
)

DOMAIN_COLUMN = "Domain"

OS_PLATFORM_COLUMN = (
    "OS Platform"
)

OS_VERSION_COLUMN = (
    "OS Version"
)

LAST_UPDATE_COLUMN = (
    "Last Device Update"
)

GROUP_COLUMN = "Group"

DEVICE_IPS_COLUMN = (
    "Device IPs"
)

EXPOSURE_LEVEL_COLUMN = (
    "Exposure Level"
)

RISK_LEVEL_COLUMN = (
    "Risk Level"
)


# --------------------------------------------------
# MDAV columns
# --------------------------------------------------

MDAV_DEVICE_ID_COLUMN = "Device ID"
MDAV_DEVICE_NAME_COLUMN = "Device name"
MDAV_DEVICE_GROUP_COLUMN = "Device group"

MDAV_OS_COLUMN = "OS"
MDAV_OS_PLATFORM_COLUMN = "OS platform"
MDAV_OS_VERSION_COLUMN = "OS version"

MDAV_AV_MODE_COLUMN = "AV mode"

MDAV_SECURITY_INTEL_VERSION_COLUMN = (
    "Security intel version"
)

MDAV_ENGINE_VERSION_COLUMN = (
    "Engine version"
)

MDAV_PLATFORM_VERSION_COLUMN = (
    "Platform version"
)

MDAV_SECURITY_INTEL_STATUS_COLUMN = (
    "Security intelligence up to date"
)

MDAV_ENGINE_STATUS_COLUMN = (
    "Engine up to date"
)

MDAV_PLATFORM_STATUS_COLUMN = (
    "Platform up to date"
)

MDAV_QUICK_SCAN_STATUS_COLUMN = (
    "Quick scan status"
)

MDAV_FULL_SCAN_STATUS_COLUMN = (
    "Full scan status"
)

MDAV_LAST_SEEN_COLUMN = (
    "Last seen"
)

MDAV_DATA_REFRESH_COLUMN = (
    "Data refresh timestamp"
)


# --------------------------------------------------
# Basic helpers
# --------------------------------------------------

def clean_value(value):

    if value is None:
        return ""

    return str(value).strip()


def normalise_device_name(
    device_name
):

    value = clean_value(
        device_name
    ).upper()


    if not value:
        return ""


    # MDAV often provides an FQDN while the
    # inventory may provide only the hostname.
    #
    # Example:
    # RGAWS100.EXAMPLECORP.LOCAL
    # becomes:
    # RGAWS100
    if "." in value:

        value = value.split(
            ".",
            1
        )[0]


    return value


def normalise_device_id(
    device_id
):

    return clean_value(
        device_id
    ).lower()


def combine_reasons(
    reasons
):

    clean_reasons = []

    seen = set()


    for reason in reasons:

        reason = clean_value(
            reason
        )


        if not reason:
            continue


        if reason in seen:
            continue


        seen.add(
            reason
        )

        clean_reasons.append(
            reason
        )


    return " | ".join(
        clean_reasons
    )


# --------------------------------------------------
# Load inventory dataset
# --------------------------------------------------

def load_dataset(
    file_path,
    region
):

    if not file_path.exists():

        raise FileNotFoundError(
            f"Dataset not found: "
            f"{file_path}"
        )


    records = []


    with open(
        file_path,
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
                f"{file_path.name} "
                f"contains no headers."
            )


        for raw_record in reader:

            record = {}


            for key, value in (
                raw_record.items()
            ):

                if key is None:
                    continue


                record[
                    clean_value(key)
                ] = clean_value(
                    value
                )


            record["Region"] = region


            records.append(
                record
            )


    return records


# --------------------------------------------------
# Load optional MDAV dataset
# --------------------------------------------------

def load_mdav_dataset():

    if not MDAV_RAW_DATASET.exists():

        return []


    records = []


    with open(
        MDAV_RAW_DATASET,
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
                f"{MDAV_RAW_DATASET.name} "
                f"contains no headers."
            )


        for raw_record in reader:

            record = {}


            for key, value in (
                raw_record.items()
            ):

                if key is None:
                    continue


                record[
                    clean_value(key)
                ] = clean_value(
                    value
                )


            records.append(
                record
            )


    return records


# --------------------------------------------------
# Inventory record completeness
# --------------------------------------------------

def record_score(
    record
):

    score = 0


    useful_fields = [
        DEVICE_ID_COLUMN,
        DEVICE_NAME_COLUMN,
        ONBOARDING_STATUS_COLUMN,
        DEVICE_TYPE_COLUMN,
        DEVICE_CATEGORY_COLUMN,
        DOMAIN_COLUMN,
        OS_PLATFORM_COLUMN,
        OS_VERSION_COLUMN,
        LAST_UPDATE_COLUMN,
        GROUP_COLUMN,
        DEVICE_IPS_COLUMN
    ]


    for field in useful_fields:

        if clean_value(
            record.get(
                field,
                ""
            )
        ):

            score += 1


    return score


# --------------------------------------------------
# Deduplicate inventory devices
# --------------------------------------------------

def deduplicate_devices(
    records
):

    devices = {}


    for record in records:

        device_name = clean_value(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:
            continue


        normalised_name = (
            normalise_device_name(
                device_name
            )
        )


        if not normalised_name:
            continue


        existing = devices.get(
            normalised_name
        )


        if existing is None:

            devices[
                normalised_name
            ] = record

            continue


        if (
            record_score(record)
            >
            record_score(existing)
        ):

            devices[
                normalised_name
            ] = record


    return devices


# --------------------------------------------------
# Build inventory indexes for MDAV matching
# --------------------------------------------------

def build_inventory_indexes(
    unique_devices
):

    device_id_index = {}

    device_name_index = {}


    for normalised_name, record in (
        unique_devices.items()
    ):

        device_name_index[
            normalised_name
        ] = record


        device_id = normalise_device_id(
            record.get(
                DEVICE_ID_COLUMN,
                ""
            )
        )


        if device_id:

            device_id_index[
                device_id
            ] = record


    return {
        "device_id_index":
            device_id_index,

        "device_name_index":
            device_name_index
    }


# --------------------------------------------------
# Onboarding status
# --------------------------------------------------

def is_onboarded(
    record
):

    status = clean_value(
        record.get(
            ONBOARDING_STATUS_COLUMN,
            ""
        )
    ).lower()


    return status == "onboarded"


def is_unsupported(
    record
):

    status = clean_value(
        record.get(
            ONBOARDING_STATUS_COLUMN,
            ""
        )
    ).lower()


    return (
        status == "unsupported"
        or "unsupported" in status
    )


# --------------------------------------------------
# Inventory sensor-data issue
# --------------------------------------------------

def get_inventory_sensor_reasons(
    record
):

    reasons = []


    for field, value in record.items():

        normalised_value = clean_value(
            value
        ).lower()


        if "no sensor data" in normalised_value:

            reasons.append(
                f"No sensor data reported in {field}"
            )


    return reasons


# --------------------------------------------------
# MDAV telemetry helpers
# --------------------------------------------------

def is_missing_telemetry_value(
    value
):

    normalised_value = clean_value(
        value
    ).lower()


    return normalised_value in {
        "",
        "0",
        "0.0",
        "0.0.0",
        "0.0.0.0",
        "unknown",
        "no data",
        "no data available",
        "not available",
        "n/a"
    }


def get_mdav_sensor_reasons(
    mdav_record
):

    reasons = []


    av_mode = clean_value(
        mdav_record.get(
            MDAV_AV_MODE_COLUMN,
            ""
        )
    )


    security_intel_version = clean_value(
        mdav_record.get(
            MDAV_SECURITY_INTEL_VERSION_COLUMN,
            ""
        )
    )


    engine_version = clean_value(
        mdav_record.get(
            MDAV_ENGINE_VERSION_COLUMN,
            ""
        )
    )


    platform_version = clean_value(
        mdav_record.get(
            MDAV_PLATFORM_VERSION_COLUMN,
            ""
        )
    )


    av_mode_lower = av_mode.lower()


    # AV mode "Other" indicates the export does not
    # have a normal Active, Passive or EDRBlocked state.
    if av_mode_lower == "other":

        reasons.append(
            "MDAV AV mode is Other"
        )


    if is_missing_telemetry_value(
        av_mode
    ):

        reasons.append(
            "MDAV AV mode is missing or unavailable"
        )


    if is_missing_telemetry_value(
        security_intel_version
    ):

        reasons.append(
            "Security intelligence version is missing or invalid"
        )


    if is_missing_telemetry_value(
        engine_version
    ):

        reasons.append(
            "Defender engine version is missing or invalid"
        )


    if is_missing_telemetry_value(
        platform_version
    ):

        reasons.append(
            "Defender platform version is missing or invalid"
        )


    return reasons


# --------------------------------------------------
# Find matching inventory device for MDAV row
#
# Match order:
#
# 1. Device ID
# 2. Normalised device name
# --------------------------------------------------

def find_inventory_record_for_mdav(
    mdav_record,
    inventory_indexes
):

    mdav_device_id = normalise_device_id(
        mdav_record.get(
            MDAV_DEVICE_ID_COLUMN,
            ""
        )
    )


    if mdav_device_id:

        matched_record = (
            inventory_indexes[
                "device_id_index"
            ].get(
                mdav_device_id
            )
        )


        if matched_record is not None:

            return {
                "record":
                    matched_record,

                "method":
                    "Device ID"
            }


    mdav_device_name = normalise_device_name(
        mdav_record.get(
            MDAV_DEVICE_NAME_COLUMN,
            ""
        )
    )


    if mdav_device_name:

        matched_record = (
            inventory_indexes[
                "device_name_index"
            ].get(
                mdav_device_name
            )
        )


        if matched_record is not None:

            return {
                "record":
                    matched_record,

                "method":
                    "Normalised Device Name"
            }


    return {
        "record":
            None,

        "method":
            "No Inventory Match"
    }


# --------------------------------------------------
# Build MDAV index
# --------------------------------------------------

def build_mdav_indexes(
    mdav_records
):

    by_device_id = {}

    by_device_name = {}


    for record in mdav_records:

        device_id = normalise_device_id(
            record.get(
                MDAV_DEVICE_ID_COLUMN,
                ""
            )
        )


        device_name = normalise_device_name(
            record.get(
                MDAV_DEVICE_NAME_COLUMN,
                ""
            )
        )


        if device_id:

            by_device_id[
                device_id
            ] = record


        if device_name:

            by_device_name[
                device_name
            ] = record


    return {
        "by_device_id":
            by_device_id,

        "by_device_name":
            by_device_name
    }


# --------------------------------------------------
# Find MDAV record for inventory device
# --------------------------------------------------

def find_mdav_record_for_inventory(
    inventory_record,
    mdav_indexes
):

    device_id = normalise_device_id(
        inventory_record.get(
            DEVICE_ID_COLUMN,
            ""
        )
    )


    if device_id:

        mdav_match = (
            mdav_indexes[
                "by_device_id"
            ].get(
                device_id
            )
        )


        if mdav_match is not None:

            return {
                "record":
                    mdav_match,

                "method":
                    "Device ID"
            }


    device_name = normalise_device_name(
        inventory_record.get(
            DEVICE_NAME_COLUMN,
            ""
        )
    )


    if device_name:

        mdav_match = (
            mdav_indexes[
                "by_device_name"
            ].get(
                device_name
            )
        )


        if mdav_match is not None:

            return {
                "record":
                    mdav_match,

                "method":
                    "Normalised Device Name"
            }


    return {
        "record":
            None,

        "method":
            "No MDAV Match"
    }


# --------------------------------------------------
# Timestamp parsing
# --------------------------------------------------

def parse_timestamp(
    value
):

    value = clean_value(
        value
    )


    if not value:
        return None


    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d",
        "%b %d, %Y %I:%M:%S %p"
    ]


    for date_format in formats:

        try:

            parsed_date = datetime.strptime(
                value,
                date_format
            )


            return parsed_date.replace(
                tzinfo=timezone.utc
            )


        except ValueError:
            continue


    try:

        parsed_date = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )


        if parsed_date.tzinfo is None:

            parsed_date = (
                parsed_date.replace(
                    tzinfo=timezone.utc
                )
            )


        return parsed_date


    except ValueError:

        return None


def get_days_since_update(
    record
):

    timestamp = parse_timestamp(
        record.get(
            LAST_UPDATE_COLUMN,
            ""
        )
    )


    if timestamp is None:
        return None


    now = datetime.now(
        timezone.utc
    )


    difference = (
        now
        - timestamp.astimezone(
            timezone.utc
        )
    )


    return difference.days


def get_stale_category(
    days_since_update
):

    if days_since_update is None:
        return ""


    if 31 <= days_since_update <= 60:

        return "31-60 Days"


    if 61 <= days_since_update <= 90:

        return "61-90 Days"


    if days_since_update > 90:

        return "Over 90 Days"


    return ""


# --------------------------------------------------
# Operating-system categorisation
# --------------------------------------------------

def get_os_category(
    record
):

    platform = clean_value(
        record.get(
            OS_PLATFORM_COLUMN,
            ""
        )
    ).lower()


    version = clean_value(
        record.get(
            OS_VERSION_COLUMN,
            ""
        )
    ).lower()


    combined = (
        platform
        + " "
        + version
    )


    if (
        "windows 11" in combined
        or "windows11" in combined
    ):

        return "Windows 11"


    if (
        "windows 10" in combined
        or "windows10" in combined
    ):

        return "Windows 10"


    if (
        "windows server" in combined
        or "windowsserver" in combined
        or "server 2025" in combined
        or "server 2022" in combined
        or "server 2019" in combined
        or "server 2016" in combined
        or "server 2012" in combined
        or "server 2008" in combined
    ):

        return "Windows Server"


    if (
        "linux" in combined
        or "ubuntu" in combined
        or "red hat" in combined
        or "rhel" in combined
        or "sles" in combined
    ):

        return "Linux"


    if (
        "macos" in combined
        or "mac os" in combined
    ):

        return "macOS"


    if (
        "android" in combined
        or "ios" in combined
    ):

        return "Mobile"


    return "Other / Unknown"


# --------------------------------------------------
# Legacy OS classification
# --------------------------------------------------

def get_legacy_os_reason(
    record
):

    platform = clean_value(
        record.get(
            OS_PLATFORM_COLUMN,
            ""
        )
    ).lower()


    version = clean_value(
        record.get(
            OS_VERSION_COLUMN,
            ""
        )
    ).lower()


    combined = (
        platform
        + " "
        + version
    )


    legacy_rules = [
        (
            "windows xp",
            "Windows XP"
        ),
        (
            "windows 7",
            "Windows 7"
        ),
        (
            "windows 8",
            "Windows 8 / 8.1"
        ),
        (
            "server 2008",
            "Windows Server 2008 / 2008 R2"
        ),
        (
            "server 2012",
            "Windows Server 2012 / 2012 R2"
        )
    ]


    for indicator, description in (
        legacy_rules
    ):

        if indicator in combined:

            return description


    if (
        "windows 10" in combined
        or "windows10" in combined
    ):

        old_windows_10_versions = [
            "1507",
            "1511",
            "1607",
            "1703",
            "1709",
            "1803",
            "1809",
            "1903",
            "1909",
            "2004",
            "20h2",
            "21h1",
            "21h2"
        ]


        for old_version in (
            old_windows_10_versions
        ):

            if old_version in combined:

                return (
                    "Legacy Windows 10 "
                    f"({old_version.upper()})"
                )


    return ""


# --------------------------------------------------
# Base output row
# --------------------------------------------------

def build_base_output(
    record
):

    return {
        "Region":
            record.get(
                "Region",
                ""
            ),

        "Device ID":
            record.get(
                DEVICE_ID_COLUMN,
                ""
            ),

        "Device Name":
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            ),

        "Normalised Device Name":
            normalise_device_name(
                record.get(
                    DEVICE_NAME_COLUMN,
                    ""
                )
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

        "Domain":
            record.get(
                DOMAIN_COLUMN,
                ""
            ),

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

        "Last Device Update":
            record.get(
                LAST_UPDATE_COLUMN,
                ""
            ),

        "Group":
            record.get(
                GROUP_COLUMN,
                ""
            ),

        "Device IPs":
            record.get(
                DEVICE_IPS_COLUMN,
                ""
            ),

        "Exposure Level":
            record.get(
                EXPOSURE_LEVEL_COLUMN,
                ""
            ),

        "Risk Level":
            record.get(
                RISK_LEVEL_COLUMN,
                ""
            )
    }


# --------------------------------------------------
# Add MDAV context to output
# --------------------------------------------------

def add_mdav_context(
    output_row,
    mdav_record,
    match_method
):

    output_row[
        "MDAV Match Method"
    ] = match_method


    if mdav_record is None:

        output_row.update({
            "MDAV Device ID": "",
            "MDAV Device Name": "",
            "MDAV Device Group": "",
            "MDAV AV Mode": "",
            "MDAV Security Intel Version": "",
            "MDAV Engine Version": "",
            "MDAV Platform Version": "",
            "MDAV Security Intelligence Up To Date": "",
            "MDAV Engine Up To Date": "",
            "MDAV Platform Up To Date": "",
            "MDAV Quick Scan Status": "",
            "MDAV Full Scan Status": "",
            "MDAV Last Seen": "",
            "MDAV Data Refresh Timestamp": ""
        })


        return output_row


    output_row.update({
        "MDAV Device ID":
            mdav_record.get(
                MDAV_DEVICE_ID_COLUMN,
                ""
            ),

        "MDAV Device Name":
            mdav_record.get(
                MDAV_DEVICE_NAME_COLUMN,
                ""
            ),

        "MDAV Device Group":
            mdav_record.get(
                MDAV_DEVICE_GROUP_COLUMN,
                ""
            ),

        "MDAV AV Mode":
            mdav_record.get(
                MDAV_AV_MODE_COLUMN,
                ""
            ),

        "MDAV Security Intel Version":
            mdav_record.get(
                MDAV_SECURITY_INTEL_VERSION_COLUMN,
                ""
            ),

        "MDAV Engine Version":
            mdav_record.get(
                MDAV_ENGINE_VERSION_COLUMN,
                ""
            ),

        "MDAV Platform Version":
            mdav_record.get(
                MDAV_PLATFORM_VERSION_COLUMN,
                ""
            ),

        "MDAV Security Intelligence Up To Date":
            mdav_record.get(
                MDAV_SECURITY_INTEL_STATUS_COLUMN,
                ""
            ),

        "MDAV Engine Up To Date":
            mdav_record.get(
                MDAV_ENGINE_STATUS_COLUMN,
                ""
            ),

        "MDAV Platform Up To Date":
            mdav_record.get(
                MDAV_PLATFORM_STATUS_COLUMN,
                ""
            ),

        "MDAV Quick Scan Status":
            mdav_record.get(
                MDAV_QUICK_SCAN_STATUS_COLUMN,
                ""
            ),

        "MDAV Full Scan Status":
            mdav_record.get(
                MDAV_FULL_SCAN_STATUS_COLUMN,
                ""
            ),

        "MDAV Last Seen":
            mdav_record.get(
                MDAV_LAST_SEEN_COLUMN,
                ""
            ),

        "MDAV Data Refresh Timestamp":
            mdav_record.get(
                MDAV_DATA_REFRESH_COLUMN,
                ""
            )
    })


    return output_row


# --------------------------------------------------
# Build consolidated no-sensor report
# --------------------------------------------------

def build_no_sensor_report(
    unique_devices,
    mdav_records
):

    sensor_issues = {}


    mdav_indexes = build_mdav_indexes(
        mdav_records
    )


    inventory_indexes = (
        build_inventory_indexes(
            unique_devices
        )
    )


    # --------------------------------------------------
    # Inventory-originated sensor issues
    # --------------------------------------------------

    for normalised_name, record in (
        unique_devices.items()
    ):

        inventory_reasons = (
            get_inventory_sensor_reasons(
                record
            )
        )


        if not inventory_reasons:
            continue


        mdav_match = (
            find_mdav_record_for_inventory(
                record,
                mdav_indexes
            )
        )


        mdav_record = mdav_match[
            "record"
        ]


        mdav_reasons = []


        if mdav_record is not None:

            mdav_reasons = (
                get_mdav_sensor_reasons(
                    mdav_record
                )
            )


        issue_key = normalised_name


        sensor_issues[
            issue_key
        ] = {
            "inventory_record":
                record,

            "mdav_record":
                mdav_record,

            "match_method":
                mdav_match[
                    "method"
                ],

            "sources":
                ["Device Inventory"],

            "reasons":
                inventory_reasons
                + mdav_reasons
        }


        if mdav_reasons:

            sensor_issues[
                issue_key
            ][
                "sources"
            ].append(
                "MDAV"
            )


    # --------------------------------------------------
    # MDAV-originated sensor issues
    # --------------------------------------------------

    for mdav_record in mdav_records:

        mdav_reasons = (
            get_mdav_sensor_reasons(
                mdav_record
            )
        )


        if not mdav_reasons:
            continue


        inventory_match = (
            find_inventory_record_for_mdav(
                mdav_record,
                inventory_indexes
            )
        )


        inventory_record = (
            inventory_match[
                "record"
            ]
        )


        mdav_name = normalise_device_name(
            mdav_record.get(
                MDAV_DEVICE_NAME_COLUMN,
                ""
            )
        )


        mdav_device_id = normalise_device_id(
            mdav_record.get(
                MDAV_DEVICE_ID_COLUMN,
                ""
            )
        )


        if inventory_record is not None:

            issue_key = normalise_device_name(
                inventory_record.get(
                    DEVICE_NAME_COLUMN,
                    ""
                )
            )

        elif mdav_name:

            issue_key = mdav_name

        else:

            issue_key = mdav_device_id


        if not issue_key:
            continue


        existing_issue = (
            sensor_issues.get(
                issue_key
            )
        )


        if existing_issue is None:

            sensor_issues[
                issue_key
            ] = {
                "inventory_record":
                    inventory_record,

                "mdav_record":
                    mdav_record,

                "match_method":
                    inventory_match[
                        "method"
                    ],

                "sources":
                    ["MDAV"],

                "reasons":
                    mdav_reasons
            }


        else:

            existing_issue[
                "mdav_record"
            ] = mdav_record


            existing_issue[
                "match_method"
            ] = inventory_match[
                "method"
            ]


            if (
                "MDAV"
                not in existing_issue[
                    "sources"
                ]
            ):

                existing_issue[
                    "sources"
                ].append(
                    "MDAV"
                )


            existing_issue[
                "reasons"
            ].extend(
                mdav_reasons
            )


    # --------------------------------------------------
    # Create final report rows
    # --------------------------------------------------

    report_rows = []


    for issue in sensor_issues.values():

        inventory_record = issue[
            "inventory_record"
        ]


        mdav_record = issue[
            "mdav_record"
        ]


        if inventory_record is not None:

            output_row = (
                build_base_output(
                    inventory_record
                )
            )


        else:

            output_row = {
                "Region": "Unknown",
                "Device ID": (
                    mdav_record.get(
                        MDAV_DEVICE_ID_COLUMN,
                        ""
                    )
                    if mdav_record
                    else ""
                ),
                "Device Name": (
                    mdav_record.get(
                        MDAV_DEVICE_NAME_COLUMN,
                        ""
                    )
                    if mdav_record
                    else ""
                ),
                "Normalised Device Name": (
                    normalise_device_name(
                        mdav_record.get(
                            MDAV_DEVICE_NAME_COLUMN,
                            ""
                        )
                    )
                    if mdav_record
                    else ""
                ),
                "Device Category": "",
                "Device Type": "",
                "Onboarding Status": "",
                "Domain": "",
                "OS Platform": (
                    mdav_record.get(
                        MDAV_OS_PLATFORM_COLUMN,
                        ""
                    )
                    if mdav_record
                    else ""
                ),
                "OS Version": (
                    mdav_record.get(
                        MDAV_OS_VERSION_COLUMN,
                        ""
                    )
                    if mdav_record
                    else ""
                ),
                "Last Device Update": "",
                "Group": (
                    mdav_record.get(
                        MDAV_DEVICE_GROUP_COLUMN,
                        ""
                    )
                    if mdav_record
                    else ""
                ),
                "Device IPs": "",
                "Exposure Level": "",
                "Risk Level": ""
            }


        output_row[
            "Sensor Issue Source"
        ] = combine_reasons(
            issue[
                "sources"
            ]
        )


        output_row[
            "Sensor Issue Type"
        ] = combine_reasons(
            issue[
                "reasons"
            ]
        )


        output_row = add_mdav_context(
            output_row,
            mdav_record,
            issue[
                "match_method"
            ]
        )


        report_rows.append(
            output_row
        )


    report_rows.sort(
        key=lambda row:
            row.get(
                "Normalised Device Name",
                ""
            )
    )


    return report_rows


# --------------------------------------------------
# Write report
# --------------------------------------------------

def write_report(
    output_file,
    records,
    empty_fieldnames=None
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    if records:

        fieldnames = list(
            records[0].keys()
        )


    elif empty_fieldnames:

        fieldnames = empty_fieldnames


    else:

        fieldnames = [
            "Region",
            "Device ID",
            "Device Name",
            "Normalised Device Name",
            "Device Category",
            "Device Type",
            "Onboarding Status",
            "Domain",
            "OS Platform",
            "OS Version",
            "Last Device Update",
            "Group",
            "Device IPs",
            "Exposure Level",
            "Risk Level"
        ]


    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )


        writer.writeheader()


        writer.writerows(
            records
        )


# --------------------------------------------------
# Analyse inventory devices
# --------------------------------------------------

def analyse_devices(
    unique_devices
):

    total_devices = len(
        unique_devices
    )


    onboarded = 0

    region_a_onboarded = 0
    region_b_onboarded = 0

    region_a_unsupported = 0
    region_b_unsupported = 0

    stale_31_60 = 0
    stale_61_90 = 0
    stale_over_90 = 0


    os_counts = {
        "Windows 11": 0,
        "Windows 10": 0,
        "Windows Server": 0,
        "Linux": 0,
        "macOS": 0,
        "Mobile": 0,
        "Other / Unknown": 0
    }


    stale_rows = []
    unsupported_rows = []
    os_rows = []
    legacy_rows = []


    for record in (
        unique_devices.values()
    ):

        region = record.get(
            "Region",
            ""
        )


        if is_onboarded(
            record
        ):

            onboarded += 1


            if region == "Region A":
                region_a_onboarded += 1


            if region == "Region B":
                region_b_onboarded += 1


        if is_unsupported(
            record
        ):

            output_row = (
                build_base_output(
                    record
                )
            )


            unsupported_rows.append(
                output_row
            )


            if region == "Region A":
                region_a_unsupported += 1


            if region == "Region B":
                region_b_unsupported += 1


        days_since_update = (
            get_days_since_update(
                record
            )
        )


        stale_category = (
            get_stale_category(
                days_since_update
            )
        )


        if stale_category:

            output_row = (
                build_base_output(
                    record
                )
            )


            output_row[
                "Days Since Last Update"
            ] = days_since_update


            output_row[
                "Stale Category"
            ] = stale_category


            stale_rows.append(
                output_row
            )


            if (
                stale_category
                == "31-60 Days"
            ):

                stale_31_60 += 1


            elif (
                stale_category
                == "61-90 Days"
            ):

                stale_61_90 += 1


            elif (
                stale_category
                == "Over 90 Days"
            ):

                stale_over_90 += 1


        os_category = (
            get_os_category(
                record
            )
        )


        os_counts[
            os_category
        ] += 1


        os_output = (
            build_base_output(
                record
            )
        )


        os_output[
            "OS Category"
        ] = os_category


        os_rows.append(
            os_output
        )


        legacy_reason = (
            get_legacy_os_reason(
                record
            )
        )


        if legacy_reason:

            legacy_output = (
                build_base_output(
                    record
                )
            )


            legacy_output[
                "Legacy OS Reason"
            ] = legacy_reason


            legacy_rows.append(
                legacy_output
            )


    if total_devices > 0:

        onboarding_coverage = (
            onboarded
            / total_devices
            * 100
        )


    else:

        onboarding_coverage = 0


    return {
        "total_devices":
            total_devices,

        "onboarded":
            onboarded,

        "onboarding_coverage":
            onboarding_coverage,

        "region_a_onboarded":
            region_a_onboarded,

        "region_b_onboarded":
            region_b_onboarded,

        "region_a_unsupported":
            region_a_unsupported,

        "region_b_unsupported":
            region_b_unsupported,

        "stale_31_60":
            stale_31_60,

        "stale_61_90":
            stale_61_90,

        "stale_over_90":
            stale_over_90,

        "windows_11":
            os_counts[
                "Windows 11"
            ],

        "windows_10":
            os_counts[
                "Windows 10"
            ],

        "windows_server":
            os_counts[
                "Windows Server"
            ],

        "linux":
            os_counts[
                "Linux"
            ],

        "macos":
            os_counts[
                "macOS"
            ],

        "mobile":
            os_counts[
                "Mobile"
            ],

        "other_unknown_os":
            os_counts[
                "Other / Unknown"
            ],

        "legacy_os":
            len(
                legacy_rows
            ),

        "stale_rows":
            stale_rows,

        "unsupported_rows":
            unsupported_rows,

        "os_rows":
            os_rows,

        "legacy_rows":
            legacy_rows
    }


# --------------------------------------------------
# Main function
# --------------------------------------------------

def run_device_metrics():

    print()

    print(
        "Starting device metrics analysis..."
    )


    region_a_records = load_dataset(
        Region A_RAW_DATASET,
        "Region A"
    )


    region_b_records = load_dataset(
        Region B_RAW_DATASET,
        "Region B"
    )


    mdav_records = (
        load_mdav_dataset()
    )


    combined_records = (
        region_a_records
        + region_b_records
    )


    unique_devices = (
        deduplicate_devices(
            combined_records
        )
    )


    results = analyse_devices(
        unique_devices
    )


    no_sensor_rows = (
        build_no_sensor_report(
            unique_devices,
            mdav_records
        )
    )


    region_a_no_sensor = sum(
        1
        for row in no_sensor_rows
        if row.get(
            "Region",
            ""
        ) == "Region A"
    )


    region_b_no_sensor = sum(
        1
        for row in no_sensor_rows
        if row.get(
            "Region",
            ""
        ) == "Region B"
    )


    unknown_region_no_sensor = sum(
        1
        for row in no_sensor_rows
        if row.get(
            "Region",
            ""
        ) not in {
            "Region A",
            "Region B"
        }
    )


    inventory_sensor_issues = sum(
        1
        for row in no_sensor_rows
        if "Device Inventory"
        in row.get(
            "Sensor Issue Source",
            ""
        )
    )


    mdav_sensor_issues = sum(
        1
        for row in no_sensor_rows
        if "MDAV"
        in row.get(
            "Sensor Issue Source",
            ""
        )
    )


    results[
        "no_sensor_rows"
    ] = no_sensor_rows


    results[
        "no_sensor_data"
    ] = len(
        no_sensor_rows
    )


    results[
        "region_a_no_sensor"
    ] = region_a_no_sensor


    results[
        "region_b_no_sensor"
    ] = region_b_no_sensor


    results[
        "unknown_region_no_sensor"
    ] = unknown_region_no_sensor


    results[
        "inventory_sensor_issues"
    ] = inventory_sensor_issues


    results[
        "mdav_sensor_issues"
    ] = mdav_sensor_issues


    results[
        "mdav_records_loaded"
    ] = len(
        mdav_records
    )


    write_report(
        STALE_OUTPUT,
        results[
            "stale_rows"
        ]
    )


    write_report(
        UNSUPPORTED_OUTPUT,
        results[
            "unsupported_rows"
        ]
    )


    no_sensor_fields = [
        "Region",
        "Device ID",
        "Device Name",
        "Normalised Device Name",
        "Device Category",
        "Device Type",
        "Onboarding Status",
        "Domain",
        "OS Platform",
        "OS Version",
        "Last Device Update",
        "Group",
        "Device IPs",
        "Exposure Level",
        "Risk Level",
        "Sensor Issue Source",
        "Sensor Issue Type",
        "MDAV Match Method",
        "MDAV Device ID",
        "MDAV Device Name",
        "MDAV Device Group",
        "MDAV AV Mode",
        "MDAV Security Intel Version",
        "MDAV Engine Version",
        "MDAV Platform Version",
        "MDAV Security Intelligence Up To Date",
        "MDAV Engine Up To Date",
        "MDAV Platform Up To Date",
        "MDAV Quick Scan Status",
        "MDAV Full Scan Status",
        "MDAV Last Seen",
        "MDAV Data Refresh Timestamp"
    ]


    write_report(
        NO_SENSOR_OUTPUT,
        results[
            "no_sensor_rows"
        ],
        empty_fieldnames=no_sensor_fields
    )


    write_report(
        OS_INVENTORY_OUTPUT,
        results[
            "os_rows"
        ]
    )


    write_report(
        LEGACY_OS_OUTPUT,
        results[
            "legacy_rows"
        ]
    )


    print()

    print(
        "Device metrics analysis completed."
    )

    print()

    print(
        f"Total unique devices: "
        f"{results['total_devices']}"
    )

    print(
        f"Total onboarded: "
        f"{results['onboarded']}"
    )

    print(
        f"Onboarding coverage: "
        f"{results['onboarding_coverage']:.1f}%"
    )

    print()

    print(
        f"Region A onboarded: "
        f"{results['region_a_onboarded']}"
    )

    print(
        f"Region B onboarded: "
        f"{results['region_b_onboarded']}"
    )

    print()

    print(
        f"MDAV records loaded: "
        f"{results['mdav_records_loaded']}"
    )

    print(
        f"Consolidated no sensor data devices: "
        f"{results['no_sensor_data']}"
    )

    print(
        f"Region A no sensor data: "
        f"{results['region_a_no_sensor']}"
    )

    print(
        f"Region B no sensor data: "
        f"{results['region_b_no_sensor']}"
    )

    print(
        f"Unknown region no sensor data: "
        f"{results['unknown_region_no_sensor']}"
    )

    print(
        f"Inventory sensor issues: "
        f"{results['inventory_sensor_issues']}"
    )

    print(
        f"MDAV telemetry issues: "
        f"{results['mdav_sensor_issues']}"
    )

    print()

    print(
        f"Region A unsupported: "
        f"{results['region_a_unsupported']}"
    )

    print(
        f"Region B unsupported: "
        f"{results['region_b_unsupported']}"
    )

    print()

    print(
        f"Stale 31-60 days: "
        f"{results['stale_31_60']}"
    )

    print(
        f"Stale 61-90 days: "
        f"{results['stale_61_90']}"
    )

    print(
        f"Stale over 90 days: "
        f"{results['stale_over_90']}"
    )

    print()

    print(
        f"Windows 11: "
        f"{results['windows_11']}"
    )

    print(
        f"Windows 10: "
        f"{results['windows_10']}"
    )

    print(
        f"Windows Server: "
        f"{results['windows_server']}"
    )

    print(
        f"Linux: "
        f"{results['linux']}"
    )

    print(
        f"macOS: "
        f"{results['macos']}"
    )

    print(
        f"Mobile: "
        f"{results['mobile']}"
    )

    print(
        f"Other / Unknown OS: "
        f"{results['other_unknown_os']}"
    )

    print()

    print(
        f"Legacy OS devices: "
        f"{results['legacy_os']}"
    )

    print()

    print(
        f"Stale report: "
        f"{STALE_OUTPUT}"
    )

    print(
        f"Unsupported report: "
        f"{UNSUPPORTED_OUTPUT}"
    )

    print(
        f"No sensor data report: "
        f"{NO_SENSOR_OUTPUT}"
    )

    print(
        f"Operating system report: "
        f"{OS_INVENTORY_OUTPUT}"
    )

    print(
        f"Legacy OS report: "
        f"{LEGACY_OS_OUTPUT}"
    )


    return results


if __name__ == "__main__":

    run_device_metrics()