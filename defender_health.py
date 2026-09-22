import csv
import re

from config import OUTPUT_DIR


MDAV_RAW_DATASET = (
    OUTPUT_DIR
    / "mdav_raw_dataset.csv"
)


DEFENDER_AV_HEALTH_OUTPUT = (
    OUTPUT_DIR
    / "defender_av_health.csv"
)

SIGNATURE_NON_COMPLIANT_OUTPUT = (
    OUTPUT_DIR
    / "defender_signature_non_compliant.csv"
)

SIGNATURE_UNKNOWN_OUTPUT = (
    OUTPUT_DIR
    / "defender_signature_unknown.csv"
)

SIGNATURE_ATTENTION_OUTPUT = (
    OUTPUT_DIR
    / "defender_signature_attention_required.csv"
)

DEFENDER_UPDATE_ISSUES_OUTPUT = (
    OUTPUT_DIR
    / "defender_update_issues.csv"
)

DEFENDER_TELEMETRY_ISSUES_OUTPUT = (
    OUTPUT_DIR
    / "defender_telemetry_issues.csv"
)

DEFENDER_SCAN_ISSUES_OUTPUT = (
    OUTPUT_DIR
    / "defender_scan_issues.csv"
)


DEVICE_ID_COLUMN = "Device ID"
DEVICE_NAME_COLUMN = "Device name"
DEVICE_GROUP_COLUMN = "Device group"

OS_COLUMN = "OS"
OS_PLATFORM_COLUMN = "OS platform"
OS_VERSION_COLUMN = "OS version"

AV_MODE_COLUMN = "AV mode"

SECURITY_INTEL_VERSION_COLUMN = (
    "Security intel version"
)

ENGINE_VERSION_COLUMN = (
    "Engine version"
)

PLATFORM_VERSION_COLUMN = (
    "Platform version"
)

QUICK_SCAN_STATUS_COLUMN = (
    "Quick scan status"
)

QUICK_SCAN_ERROR_COLUMN = (
    "Quick scan error"
)

FULL_SCAN_STATUS_COLUMN = (
    "Full scan status"
)

FULL_SCAN_ERROR_COLUMN = (
    "Full scan error"
)

QUICK_SCAN_TIME_COLUMN = (
    "Quick scan time"
)

FULL_SCAN_TIME_COLUMN = (
    "Full scan time"
)

LAST_SEEN_COLUMN = "Last seen"

DATA_REFRESH_COLUMN = (
    "Data refresh timestamp"
)

ENGINE_UPDATE_TIME_COLUMN = (
    "Engine update time"
)

SIGNATURE_UPDATE_TIME_COLUMN = (
    "Signature update time"
)

PLATFORM_UPDATE_TIME_COLUMN = (
    "Platform update time"
)

SECURITY_INTEL_STATUS_COLUMN = (
    "Security intelligence up to date"
)

ENGINE_STATUS_COLUMN = (
    "Engine up to date"
)

PLATFORM_STATUS_COLUMN = (
    "Platform up to date"
)

SECURITY_INTEL_PUBLISH_TIME_COLUMN = (
    "Security intel publish time"
)

SIGNATURE_REFRESH_TIME_COLUMN = (
    "Signature refresh time"
)

EBPF_STATUS_COLUMN = "eBPF status"


def clean_value(value):

    if value is None:
        return ""

    return str(value).strip()


def normalise_device_name(device_name):

    value = clean_value(
        device_name
    ).upper()

    if not value:
        return ""

    if "." in value:

        value = value.split(
            ".",
            1
        )[0]

    return value


def normalise_device_id(device_id):

    return clean_value(
        device_id
    ).lower()


def normalise_status(value):

    return clean_value(
        value
    ).lower()


def is_missing_value(value):

    return normalise_status(
        value
    ) in {
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


def load_mdav_dataset():

    if not MDAV_RAW_DATASET.exists():

        raise FileNotFoundError(
            f"MDAV raw dataset not found: "
            f"{MDAV_RAW_DATASET}"
        )

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

            for key, value in raw_record.items():

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

    if not records:

        raise ValueError(
            f"{MDAV_RAW_DATASET.name} "
            f"contains no records."
        )

    return records


def mdav_record_score(record):

    useful_fields = [
        DEVICE_ID_COLUMN,
        DEVICE_NAME_COLUMN,
        AV_MODE_COLUMN,
        SECURITY_INTEL_VERSION_COLUMN,
        ENGINE_VERSION_COLUMN,
        PLATFORM_VERSION_COLUMN,
        SECURITY_INTEL_STATUS_COLUMN,
        ENGINE_STATUS_COLUMN,
        PLATFORM_STATUS_COLUMN,
        LAST_SEEN_COLUMN
    ]

    score = 0

    for field in useful_fields:

        if clean_value(
            record.get(
                field,
                ""
            )
        ):

            score += 1

    return score


def deduplicate_mdav_devices(records):

    devices = {}

    for record in records:

        device_id = normalise_device_id(
            record.get(
                DEVICE_ID_COLUMN,
                ""
            )
        )

        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )

        if device_id:

            device_key = (
                "ID:"
                + device_id
            )

        elif device_name:

            device_key = (
                "NAME:"
                + device_name
            )

        else:

            continue

        existing = devices.get(
            device_key
        )

        if existing is None:

            devices[
                device_key
            ] = record

            continue

        if (
            mdav_record_score(record)
            >
            mdav_record_score(existing)
        ):

            devices[
                device_key
            ] = record

    return devices


def parse_version(value):

    value = clean_value(
        value
    )

    if is_missing_value(
        value
    ):

        return ()

    numeric_parts = re.findall(
        r"\d+",
        value
    )

    if not numeric_parts:
        return ()

    return tuple(
        int(part)
        for part in numeric_parts
    )


def get_latest_observed_version(
    records,
    column_name
):

    latest_text = ""

    latest_tuple = ()

    for record in records:

        version_text = clean_value(
            record.get(
                column_name,
                ""
            )
        )

        version_tuple = parse_version(
            version_text
        )

        if not version_tuple:
            continue

        if version_tuple > latest_tuple:

            latest_tuple = version_tuple
            latest_text = version_text

    return latest_text


def classify_update_status(
    status_value,
    version_value
):

    status = normalise_status(
        status_value
    )

    if is_missing_value(
        version_value
    ):

        return "UNKNOWN"

    if status == "yes":

        return "COMPLIANT"

    if status == "no":

        return "NON-COMPLIANT"

    return "UNKNOWN"


def classify_signature_status(record):

    return classify_update_status(
        record.get(
            SECURITY_INTEL_STATUS_COLUMN,
            ""
        ),
        record.get(
            SECURITY_INTEL_VERSION_COLUMN,
            ""
        )
    )


def classify_engine_status(record):

    return classify_update_status(
        record.get(
            ENGINE_STATUS_COLUMN,
            ""
        ),
        record.get(
            ENGINE_VERSION_COLUMN,
            ""
        )
    )


def classify_platform_status(record):

    return classify_update_status(
        record.get(
            PLATFORM_STATUS_COLUMN,
            ""
        ),
        record.get(
            PLATFORM_VERSION_COLUMN,
            ""
        )
    )


def get_telemetry_reasons(record):

    reasons = []

    av_mode = clean_value(
        record.get(
            AV_MODE_COLUMN,
            ""
        )
    )

    security_intel_version = clean_value(
        record.get(
            SECURITY_INTEL_VERSION_COLUMN,
            ""
        )
    )

    engine_version = clean_value(
        record.get(
            ENGINE_VERSION_COLUMN,
            ""
        )
    )

    platform_version = clean_value(
        record.get(
            PLATFORM_VERSION_COLUMN,
            ""
        )
    )

    if normalise_status(av_mode) == "other":

        reasons.append(
            "AV mode is Other"
        )

    if is_missing_value(av_mode):

        reasons.append(
            "AV mode missing or unavailable"
        )

    if is_missing_value(
        security_intel_version
    ):

        reasons.append(
            "Security intelligence version missing or invalid"
        )

    if is_missing_value(
        engine_version
    ):

        reasons.append(
            "Engine version missing or invalid"
        )

    if is_missing_value(
        platform_version
    ):

        reasons.append(
            "Platform version missing or invalid"
        )

    return reasons


def classify_scan_status(value):

    status = normalise_status(
        value
    )

    if status == "completed":

        return "COMPLETED"

    if status in {
        "doesn't apply",
        "does not apply",
        "not applicable"
    }:

        return "NOT APPLICABLE"

    if status in {
        "cancelled",
        "canceled",
        "failed",
        "error"
    }:

        return "ISSUE"

    return "NO DATA"


def build_base_output(record):

    signature_classification = (
        classify_signature_status(
            record
        )
    )

    engine_classification = (
        classify_engine_status(
            record
        )
    )

    platform_classification = (
        classify_platform_status(
            record
        )
    )

    quick_scan_classification = (
        classify_scan_status(
            record.get(
                QUICK_SCAN_STATUS_COLUMN,
                ""
            )
        )
    )

    full_scan_classification = (
        classify_scan_status(
            record.get(
                FULL_SCAN_STATUS_COLUMN,
                ""
            )
        )
    )

    return {
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

        "Device Group":
            record.get(
                DEVICE_GROUP_COLUMN,
                ""
            ),

        "OS":
            record.get(
                OS_COLUMN,
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

        "AV Mode":
            record.get(
                AV_MODE_COLUMN,
                ""
            ),

        "Security Intelligence Version":
            record.get(
                SECURITY_INTEL_VERSION_COLUMN,
                ""
            ),

        "Signature Compliance Classification":
            signature_classification,

        "Security Intelligence Up To Date":
            record.get(
                SECURITY_INTEL_STATUS_COLUMN,
                ""
            ),

        "Engine Version":
            record.get(
                ENGINE_VERSION_COLUMN,
                ""
            ),

        "Engine Compliance Classification":
            engine_classification,

        "Engine Up To Date":
            record.get(
                ENGINE_STATUS_COLUMN,
                ""
            ),

        "Platform Version":
            record.get(
                PLATFORM_VERSION_COLUMN,
                ""
            ),

        "Platform Compliance Classification":
            platform_classification,

        "Platform Up To Date":
            record.get(
                PLATFORM_STATUS_COLUMN,
                ""
            ),

        "Quick Scan Status":
            record.get(
                QUICK_SCAN_STATUS_COLUMN,
                ""
            ),

        "Quick Scan Classification":
            quick_scan_classification,

        "Quick Scan Error":
            record.get(
                QUICK_SCAN_ERROR_COLUMN,
                ""
            ),

        "Quick Scan Time":
            record.get(
                QUICK_SCAN_TIME_COLUMN,
                ""
            ),

        "Full Scan Status":
            record.get(
                FULL_SCAN_STATUS_COLUMN,
                ""
            ),

        "Full Scan Classification":
            full_scan_classification,

        "Full Scan Error":
            record.get(
                FULL_SCAN_ERROR_COLUMN,
                ""
            ),

        "Full Scan Time":
            record.get(
                FULL_SCAN_TIME_COLUMN,
                ""
            ),

        "Last Seen":
            record.get(
                LAST_SEEN_COLUMN,
                ""
            ),

        "Data Refresh Timestamp":
            record.get(
                DATA_REFRESH_COLUMN,
                ""
            ),

        "Engine Update Time":
            record.get(
                ENGINE_UPDATE_TIME_COLUMN,
                ""
            ),

        "Signature Update Time":
            record.get(
                SIGNATURE_UPDATE_TIME_COLUMN,
                ""
            ),

        "Platform Update Time":
            record.get(
                PLATFORM_UPDATE_TIME_COLUMN,
                ""
            ),

        "Security Intel Publish Time":
            record.get(
                SECURITY_INTEL_PUBLISH_TIME_COLUMN,
                ""
            ),

        "Signature Refresh Time":
            record.get(
                SIGNATURE_REFRESH_TIME_COLUMN,
                ""
            ),

        "eBPF Status":
            record.get(
                EBPF_STATUS_COLUMN,
                ""
            )
    }


def write_report(
    output_file,
    records
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if records:

        fieldnames = list(
            records[0].keys()
        )

    else:

        fieldnames = [
            "Device ID",
            "Device Name",
            "Normalised Device Name",
            "Device Group",
            "OS",
            "OS Platform",
            "OS Version",
            "AV Mode",
            "Security Intelligence Version",
            "Signature Compliance Classification",
            "Security Intelligence Up To Date",
            "Engine Version",
            "Engine Compliance Classification",
            "Engine Up To Date",
            "Platform Version",
            "Platform Compliance Classification",
            "Platform Up To Date",
            "Quick Scan Status",
            "Quick Scan Classification",
            "Quick Scan Error",
            "Quick Scan Time",
            "Full Scan Status",
            "Full Scan Classification",
            "Full Scan Error",
            "Full Scan Time",
            "Last Seen",
            "Data Refresh Timestamp",
            "Engine Update Time",
            "Signature Update Time",
            "Platform Update Time",
            "Security Intel Publish Time",
            "Signature Refresh Time",
            "eBPF Status"
        ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()

        writer.writerows(
            records
        )


def analyse_defender_health(
    unique_devices
):

    records = list(
        unique_devices.values()
    )

    total_reporting_devices = len(
        records
    )

    av_active = 0
    av_passive = 0
    edr_blocked = 0
    av_other = 0
    av_unknown = 0

    signature_compliant = 0
    signature_non_compliant = 0
    signature_unknown = 0

    engine_compliant = 0
    engine_non_compliant = 0
    engine_unknown = 0

    platform_compliant = 0
    platform_non_compliant = 0
    platform_unknown = 0

    quick_scan_completed = 0
    quick_scan_issues = 0
    quick_scan_no_data = 0
    quick_scan_not_applicable = 0

    full_scan_completed = 0
    full_scan_issues = 0
    full_scan_no_data = 0
    full_scan_not_applicable = 0

    health_rows = []
    signature_non_compliant_rows = []
    signature_unknown_rows = []
    signature_attention_rows = []
    update_issue_rows = []
    telemetry_issue_rows = []
    scan_issue_rows = []

    for record in records:

        output_row = build_base_output(
            record
        )

        health_rows.append(
            output_row
        )

        av_mode = normalise_status(
            record.get(
                AV_MODE_COLUMN,
                ""
            )
        )

        if av_mode == "active":

            av_active += 1

        elif av_mode == "passive":

            av_passive += 1

        elif av_mode == "edrblocked":

            edr_blocked += 1

        elif av_mode == "other":

            av_other += 1

        else:

            av_unknown += 1

        signature_classification = (
            output_row[
                "Signature Compliance Classification"
            ]
        )

        if signature_classification == "COMPLIANT":

            signature_compliant += 1

        elif signature_classification == "NON-COMPLIANT":

            signature_non_compliant += 1

            non_compliant_row = (
                output_row.copy()
            )

            non_compliant_row[
                "Attention Reason"
            ] = (
                "Security intelligence is not up to date"
            )

            signature_non_compliant_rows.append(
                non_compliant_row
            )

            signature_attention_rows.append(
                non_compliant_row.copy()
            )

        else:

            signature_unknown += 1

            unknown_row = (
                output_row.copy()
            )

            unknown_row[
                "Attention Reason"
            ] = (
                "Security intelligence compliance "
                "status is unknown or telemetry is invalid"
            )

            signature_unknown_rows.append(
                unknown_row
            )

            signature_attention_rows.append(
                unknown_row.copy()
            )

        engine_classification = (
            output_row[
                "Engine Compliance Classification"
            ]
        )

        if engine_classification == "COMPLIANT":

            engine_compliant += 1

        elif engine_classification == "NON-COMPLIANT":

            engine_non_compliant += 1

        else:

            engine_unknown += 1

        platform_classification = (
            output_row[
                "Platform Compliance Classification"
            ]
        )

        if platform_classification == "COMPLIANT":

            platform_compliant += 1

        elif platform_classification == "NON-COMPLIANT":

            platform_non_compliant += 1

        else:

            platform_unknown += 1

        update_reasons = []

        if (
            signature_classification
            != "COMPLIANT"
        ):

            update_reasons.append(
                "Security intelligence requires attention"
            )

        if (
            engine_classification
            != "COMPLIANT"
        ):

            update_reasons.append(
                "Engine requires attention"
            )

        if (
            platform_classification
            != "COMPLIANT"
        ):

            update_reasons.append(
                "Platform requires attention"
            )

        if update_reasons:

            update_row = (
                output_row.copy()
            )

            update_row[
                "Update Issue Reason"
            ] = " | ".join(
                update_reasons
            )

            update_issue_rows.append(
                update_row
            )

        telemetry_reasons = (
            get_telemetry_reasons(
                record
            )
        )

        if telemetry_reasons:

            telemetry_row = (
                output_row.copy()
            )

            telemetry_row[
                "Telemetry Issue Reason"
            ] = " | ".join(
                telemetry_reasons
            )

            telemetry_issue_rows.append(
                telemetry_row
            )

        quick_classification = (
            output_row[
                "Quick Scan Classification"
            ]
        )

        if quick_classification == "COMPLETED":

            quick_scan_completed += 1

        elif quick_classification == "ISSUE":

            quick_scan_issues += 1

        elif quick_classification == "NOT APPLICABLE":

            quick_scan_not_applicable += 1

        else:

            quick_scan_no_data += 1

        full_classification = (
            output_row[
                "Full Scan Classification"
            ]
        )

        if full_classification == "COMPLETED":

            full_scan_completed += 1

        elif full_classification == "ISSUE":

            full_scan_issues += 1

        elif full_classification == "NOT APPLICABLE":

            full_scan_not_applicable += 1

        else:

            full_scan_no_data += 1

        scan_reasons = []

        if quick_classification in {
            "ISSUE",
            "NO DATA"
        }:

            scan_reasons.append(
                "Quick scan requires attention"
            )

        if full_classification in {
            "ISSUE",
            "NO DATA"
        }:

            scan_reasons.append(
                "Full scan requires attention"
            )

        if scan_reasons:

            scan_row = (
                output_row.copy()
            )

            scan_row[
                "Scan Issue Reason"
            ] = " | ".join(
                scan_reasons
            )

            scan_issue_rows.append(
                scan_row
            )

    eligible_signature_devices = (
        signature_compliant
        + signature_non_compliant
    )

    if eligible_signature_devices > 0:

        signature_compliance_rate = (
            signature_compliant
            / eligible_signature_devices
            * 100
        )

    else:

        signature_compliance_rate = 0

    eligible_engine_devices = (
        engine_compliant
        + engine_non_compliant
    )

    if eligible_engine_devices > 0:

        engine_compliance_rate = (
            engine_compliant
            / eligible_engine_devices
            * 100
        )

    else:

        engine_compliance_rate = 0

    eligible_platform_devices = (
        platform_compliant
        + platform_non_compliant
    )

    if eligible_platform_devices > 0:

        platform_compliance_rate = (
            platform_compliant
            / eligible_platform_devices
            * 100
        )

    else:

        platform_compliance_rate = 0

    latest_security_intel = (
        get_latest_observed_version(
            records,
            SECURITY_INTEL_VERSION_COLUMN
        )
    )

    latest_engine = (
        get_latest_observed_version(
            records,
            ENGINE_VERSION_COLUMN
        )
    )

    latest_platform = (
        get_latest_observed_version(
            records,
            PLATFORM_VERSION_COLUMN
        )
    )

    latest_security_intel_devices = sum(
        1
        for record in records
        if clean_value(
            record.get(
                SECURITY_INTEL_VERSION_COLUMN,
                ""
            )
        ) == latest_security_intel
    )

    latest_engine_devices = sum(
        1
        for record in records
        if clean_value(
            record.get(
                ENGINE_VERSION_COLUMN,
                ""
            )
        ) == latest_engine
    )

    latest_platform_devices = sum(
        1
        for record in records
        if clean_value(
            record.get(
                PLATFORM_VERSION_COLUMN,
                ""
            )
        ) == latest_platform
    )

    return {
        "total_reporting_devices":
            total_reporting_devices,

        "av_active":
            av_active,

        "av_passive":
            av_passive,

        "edr_blocked":
            edr_blocked,

        "av_other":
            av_other,

        "av_unknown":
            av_unknown,

        "signature_compliant":
            signature_compliant,

        "signature_non_compliant":
            signature_non_compliant,

        "signature_unknown":
            signature_unknown,

        "signature_compliance_rate":
            signature_compliance_rate,

        "engine_compliant":
            engine_compliant,

        "engine_non_compliant":
            engine_non_compliant,

        "engine_unknown":
            engine_unknown,

        "engine_compliance_rate":
            engine_compliance_rate,

        "platform_compliant":
            platform_compliant,

        "platform_non_compliant":
            platform_non_compliant,

        "platform_unknown":
            platform_unknown,

        "platform_compliance_rate":
            platform_compliance_rate,

        "latest_security_intel":
            latest_security_intel,

        "latest_security_intel_devices":
            latest_security_intel_devices,

        "latest_engine":
            latest_engine,

        "latest_engine_devices":
            latest_engine_devices,

        "latest_platform":
            latest_platform,

        "latest_platform_devices":
            latest_platform_devices,

        "quick_scan_completed":
            quick_scan_completed,

        "quick_scan_issues":
            quick_scan_issues,

        "quick_scan_no_data":
            quick_scan_no_data,

        "quick_scan_not_applicable":
            quick_scan_not_applicable,

        "full_scan_completed":
            full_scan_completed,

        "full_scan_issues":
            full_scan_issues,

        "full_scan_no_data":
            full_scan_no_data,

        "full_scan_not_applicable":
            full_scan_not_applicable,

        "telemetry_issues":
            len(
                telemetry_issue_rows
            ),

        "health_rows":
            health_rows,

        "signature_non_compliant_rows":
            signature_non_compliant_rows,

        "signature_unknown_rows":
            signature_unknown_rows,

        "signature_attention_rows":
            signature_attention_rows,

        "update_issue_rows":
            update_issue_rows,

        "telemetry_issue_rows":
            telemetry_issue_rows,

        "scan_issue_rows":
            scan_issue_rows
    }


def run_defender_health():

    print()

    print(
        "Starting Defender health analysis..."
    )

    mdav_records = (
        load_mdav_dataset()
    )

    unique_devices = (
        deduplicate_mdav_devices(
            mdav_records
        )
    )

    results = analyse_defender_health(
        unique_devices
    )

    write_report(
        DEFENDER_AV_HEALTH_OUTPUT,
        results[
            "health_rows"
        ]
    )

    write_report(
        SIGNATURE_NON_COMPLIANT_OUTPUT,
        results[
            "signature_non_compliant_rows"
        ]
    )

    write_report(
        SIGNATURE_UNKNOWN_OUTPUT,
        results[
            "signature_unknown_rows"
        ]
    )

    write_report(
        SIGNATURE_ATTENTION_OUTPUT,
        results[
            "signature_attention_rows"
        ]
    )

    write_report(
        DEFENDER_UPDATE_ISSUES_OUTPUT,
        results[
            "update_issue_rows"
        ]
    )

    write_report(
        DEFENDER_TELEMETRY_ISSUES_OUTPUT,
        results[
            "telemetry_issue_rows"
        ]
    )

    write_report(
        DEFENDER_SCAN_ISSUES_OUTPUT,
        results[
            "scan_issue_rows"
        ]
    )

    print()

    print(
        "Defender health analysis completed."
    )

    print()

    print(
        f"MDAV records loaded: "
        f"{len(mdav_records)}"
    )

    print(
        f"Unique AV reporting devices: "
        f"{results['total_reporting_devices']}"
    )

    print()

    print(
        f"AV Active: "
        f"{results['av_active']}"
    )

    print(
        f"AV Passive: "
        f"{results['av_passive']}"
    )

    print(
        f"EDR Blocked: "
        f"{results['edr_blocked']}"
    )

    print(
        f"AV Other: "
        f"{results['av_other']}"
    )

    print(
        f"AV Unknown: "
        f"{results['av_unknown']}"
    )

    print()

    print(
        f"Signature compliance rate: "
        f"{results['signature_compliance_rate']:.1f}%"
    )

    print(
        f"Signatures up to date: "
        f"{results['signature_compliant']}"
    )

    print(
        f"Signatures non-compliant: "
        f"{results['signature_non_compliant']}"
    )

    print(
        f"Signature status unknown: "
        f"{results['signature_unknown']}"
    )

    print()

    print(
        f"Engine compliance rate: "
        f"{results['engine_compliance_rate']:.1f}%"
    )

    print(
        f"Engine non-compliant: "
        f"{results['engine_non_compliant']}"
    )

    print(
        f"Engine status unknown: "
        f"{results['engine_unknown']}"
    )

    print()

    print(
        f"Platform compliance rate: "
        f"{results['platform_compliance_rate']:.1f}%"
    )

    print(
        f"Platform non-compliant: "
        f"{results['platform_non_compliant']}"
    )

    print(
        f"Platform status unknown: "
        f"{results['platform_unknown']}"
    )

    print()

    print(
        f"Latest observed security intelligence: "
        f"{results['latest_security_intel']}"
    )

    print(
        f"Devices on latest observed security intelligence: "
        f"{results['latest_security_intel_devices']}"
    )

    print(
        f"Latest observed engine: "
        f"{results['latest_engine']}"
    )

    print(
        f"Devices on latest observed engine: "
        f"{results['latest_engine_devices']}"
    )

    print(
        f"Latest observed platform: "
        f"{results['latest_platform']}"
    )

    print(
        f"Devices on latest observed platform: "
        f"{results['latest_platform_devices']}"
    )

    print()

    print(
        f"Quick scans completed: "
        f"{results['quick_scan_completed']}"
    )

    print(
        f"Quick scan issues: "
        f"{results['quick_scan_issues']}"
    )

    print(
        f"Quick scan no data: "
        f"{results['quick_scan_no_data']}"
    )

    print()

    print(
        f"Full scans completed: "
        f"{results['full_scan_completed']}"
    )

    print(
        f"Full scan issues: "
        f"{results['full_scan_issues']}"
    )

    print(
        f"Full scan no data: "
        f"{results['full_scan_no_data']}"
    )

    print()

    print(
        f"Telemetry issues: "
        f"{results['telemetry_issues']}"
    )

    print()

    print(
        f"Defender AV health report: "
        f"{DEFENDER_AV_HEALTH_OUTPUT}"
    )

    print(
        f"Signature non-compliant report: "
        f"{SIGNATURE_NON_COMPLIANT_OUTPUT}"
    )

    print(
        f"Signature unknown report: "
        f"{SIGNATURE_UNKNOWN_OUTPUT}"
    )

    print(
        f"Signature attention report: "
        f"{SIGNATURE_ATTENTION_OUTPUT}"
    )

    print(
        f"Update issues report: "
        f"{DEFENDER_UPDATE_ISSUES_OUTPUT}"
    )

    print(
        f"Telemetry issues report: "
        f"{DEFENDER_TELEMETRY_ISSUES_OUTPUT}"
    )

    print(
        f"Scan issues report: "
        f"{DEFENDER_SCAN_ISSUES_OUTPUT}"
    )

    return results


if __name__ == "__main__":

    run_defender_health()