import pandas as pd
import streamlit as st

from config import OUTPUT_DIR


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="CORP Security Coverage Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Report files
# --------------------------------------------------

REPORT_FILES = {
    "Possible Onboarding Candidates":
        OUTPUT_DIR / "possible_onboarding_candidates.csv",

    "Possible Onboarding - Investigation Required":
        OUTPUT_DIR / "investigation_required.csv",

    "Unknown Devices Using CORP Internal IP":
        OUTPUT_DIR / "internal_ip_investigate.csv",

    "False Can Be Onboarded Status":
        OUTPUT_DIR / "already_onboarded_devices.csv",

    "Excluded Onboarding Candidates":
        OUTPUT_DIR / "excluded_onboarding_candidates.csv",

    "No Sensor Data":
        OUTPUT_DIR / "no_sensor_data.csv",

    "Unsupported Devices":
        OUTPUT_DIR / "unsupported_devices.csv",

    "Stale Devices":
        OUTPUT_DIR / "stale_devices.csv",

    "Operating System Inventory":
        OUTPUT_DIR / "operating_system_inventory.csv",

    "Legacy OS Devices":
        OUTPUT_DIR / "legacy_os_devices.csv",

    "Defender AV Health":
        OUTPUT_DIR / "defender_av_health.csv",

    "Defender Signature Non-Compliant":
        OUTPUT_DIR / "defender_signature_non_compliant.csv",

    "Defender Signature Unknown":
        OUTPUT_DIR / "defender_signature_unknown.csv",

    "Defender Signature Attention Required":
        OUTPUT_DIR / "defender_signature_attention_required.csv",

    "Defender Update Issues":
        OUTPUT_DIR / "defender_update_issues.csv",

    "Defender Telemetry Issues":
        OUTPUT_DIR / "defender_telemetry_issues.csv",

    "Defender Scan Issues":
        OUTPUT_DIR / "defender_scan_issues.csv",

    "Discovered Naming Families":
        OUTPUT_DIR / "discovered_naming_families.csv",

    "Discovered Naming Patterns":
        OUTPUT_DIR / "discovered_naming_patterns.csv",

    "Region A Raw Dataset":
        OUTPUT_DIR / "region_a_raw_dataset.csv",

    "Region B Raw Dataset":
        OUTPUT_DIR / "region_b_raw_dataset.csv",

    "MDAV Raw Dataset":
        OUTPUT_DIR / "mdav_raw_dataset.csv",

    "Combined Raw Dataset":
        OUTPUT_DIR / "combined_raw_dataset.csv"
}


# --------------------------------------------------
# Session state
# --------------------------------------------------

if "analysis_complete" not in st.session_state:
    st.session_state["analysis_complete"] = False


if "reports" not in st.session_state:
    st.session_state["reports"] = {}


if "summary" not in st.session_state:
    st.session_state["summary"] = {}


if "uploaded_file_names" not in st.session_state:
    st.session_state["uploaded_file_names"] = []


# --------------------------------------------------
# CSV helpers
# --------------------------------------------------

def read_report(file_path):

    if not file_path.exists():
        return pd.DataFrame()


    try:

        return pd.read_csv(
            file_path,
            encoding="utf-8-sig",
            dtype=str,
            keep_default_na=False
        )


    except UnicodeDecodeError:

        return pd.read_csv(
            file_path,
            encoding="cp1252",
            dtype=str,
            keep_default_na=False
        )


    except pd.errors.EmptyDataError:

        return pd.DataFrame()


def load_reports():

    reports = {}


    for report_name, file_path in REPORT_FILES.items():

        reports[report_name] = read_report(
            file_path
        )


    return reports


def dataframe_to_csv(dataframe):

    return dataframe.to_csv(
        index=False
    ).encode(
        "utf-8-sig"
    )


def count_unique_devices(dataframe):

    if dataframe.empty:
        return 0


    candidate_columns = [
        "Normalised Device Name",
        "Device Name",
        "Original Device Name",
        "Device ID"
    ]


    for column in candidate_columns:

        if column not in dataframe.columns:
            continue


        values = (
            dataframe[column]
            .astype(str)
            .str.strip()
            .str.upper()
        )


        values = values[
            values != ""
        ]


        if len(values) > 0:

            return int(
                values.nunique()
            )


    return int(
        len(dataframe)
    )


# --------------------------------------------------
# Run complete backend pipeline
# --------------------------------------------------

def run_complete_analysis(
    inventory_file_1,
    inventory_file_2,
    mdav_file
):

    from loader import load_uploaded_inputs
    from naming_rules import initialise_naming_rules
    from pattern_discovery import run_pattern_discovery
    from matching import run_matching
    from internal_network import run_internal_network
    from onboarded_devices import run_onboarded_devices
    from device_metrics import run_device_metrics
    from defender_health import run_defender_health


    # --------------------------------------------------
    # Load inputs
    #
    # loader.py automatically determines which
    # inventory export is Region A and which is Region B.
    # --------------------------------------------------

    combined_records = load_uploaded_inputs(
        inventory_file_1,
        inventory_file_2,
        mdav_file
    )


    # --------------------------------------------------
    # Naming rules
    # --------------------------------------------------

    reference_data = initialise_naming_rules()


    # --------------------------------------------------
    # Naming pattern discovery
    # --------------------------------------------------

    run_pattern_discovery(
        combined_records
    )


    # --------------------------------------------------
    # Onboarding matching
    # --------------------------------------------------

    matching_results = run_matching(
        combined_records,
        reference_data
    )


    # --------------------------------------------------
    # Internal network investigation
    # --------------------------------------------------

    internal_results = run_internal_network(
        matching_results[
            "investigation_required"
        ]
    )


    # --------------------------------------------------
    # Regional onboarding metrics
    # --------------------------------------------------

    onboarded_results = run_onboarded_devices()


    # --------------------------------------------------
    # Device health / OS / stale / sensor metrics
    # --------------------------------------------------

    device_results = run_device_metrics()


    # --------------------------------------------------
    # Defender Antivirus health
    # --------------------------------------------------

    defender_results = run_defender_health()


    # --------------------------------------------------
    # Build dashboard summary
    # --------------------------------------------------

    summary = {
        "total_devices":
            device_results[
                "total_devices"
            ],

        "onboarding_coverage":
            device_results[
                "onboarding_coverage"
            ],

        "region_a_onboarded":
            onboarded_results[
                "region_a_onboarded"
            ],

        "region_b_onboarded":
            onboarded_results[
                "region_b_onboarded"
            ],

        "region_a_servers_onboarded":
            onboarded_results[
                "region_a_servers_onboarded"
            ],

        "region_b_servers_onboarded":
            onboarded_results[
                "region_b_servers_onboarded"
            ],

        "possible_candidates":
            len(
                matching_results[
                    "possible_candidates"
                ]
            ),

        "investigation_required":
            len(
                matching_results[
                    "investigation_required"
                ]
            ),

        "internal_ip_investigate":
            internal_results[
                "devices_with_internal_match"
            ],

        "false_can_be_onboarded":
            len(
                matching_results[
                    "already_onboarded"
                ]
            ),

        "region_a_no_sensor":
            device_results[
                "region_a_no_sensor"
            ],

        "region_b_no_sensor":
            device_results[
                "region_b_no_sensor"
            ],

        "total_no_sensor":
            device_results[
                "no_sensor_data"
            ],

        "region_a_unsupported":
            device_results[
                "region_a_unsupported"
            ],

        "region_b_unsupported":
            device_results[
                "region_b_unsupported"
            ],

        "stale_31_60":
            device_results[
                "stale_31_60"
            ],

        "stale_61_90":
            device_results[
                "stale_61_90"
            ],

        "stale_over_90":
            device_results[
                "stale_over_90"
            ],

        "windows_11":
            device_results[
                "windows_11"
            ],

        "windows_10":
            device_results[
                "windows_10"
            ],

        "windows_server":
            device_results[
                "windows_server"
            ],

        "linux":
            device_results[
                "linux"
            ],

        "other_unknown_os":
            device_results[
                "other_unknown_os"
            ],

        "legacy_os":
            device_results[
                "legacy_os"
            ],

        "av_reporting_devices":
            defender_results[
                "total_reporting_devices"
            ],

        "av_active":
            defender_results[
                "av_active"
            ],

        "av_passive":
            defender_results[
                "av_passive"
            ],

        "edr_blocked":
            defender_results[
                "edr_blocked"
            ],

        "av_other":
            defender_results[
                "av_other"
            ],

        "signature_compliance_rate":
            defender_results[
                "signature_compliance_rate"
            ],

        "signature_compliant":
            defender_results[
                "signature_compliant"
            ],

        "signature_non_compliant":
            defender_results[
                "signature_non_compliant"
            ],

        "signature_unknown":
            defender_results[
                "signature_unknown"
            ],

        "engine_compliance_rate":
            defender_results[
                "engine_compliance_rate"
            ],

        "engine_non_compliant":
            defender_results[
                "engine_non_compliant"
            ],

        "platform_compliance_rate":
            defender_results[
                "platform_compliance_rate"
            ],

        "platform_non_compliant":
            defender_results[
                "platform_non_compliant"
            ],

        "latest_security_intel":
            defender_results[
                "latest_security_intel"
            ],

        "latest_engine":
            defender_results[
                "latest_engine"
            ],

        "latest_platform":
            defender_results[
                "latest_platform"
            ],

        "quick_scan_completed":
            defender_results[
                "quick_scan_completed"
            ],

        "quick_scan_issues":
            defender_results[
                "quick_scan_issues"
            ],

        "full_scan_completed":
            defender_results[
                "full_scan_completed"
            ],

        "full_scan_issues":
            defender_results[
                "full_scan_issues"
            ],

        "telemetry_issues":
            defender_results[
                "telemetry_issues"
            ]
    }


    reports = load_reports()


    return reports, summary


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title(
    "CORP Security Coverage Dashboard"
)

st.caption(
    "Endpoint onboarding, device health and Microsoft Defender "
    "Antivirus reporting."
)


# --------------------------------------------------
# Input section
# --------------------------------------------------

with st.container(border=True):

    st.subheader(
        "Reports"
    )


    st.caption(
        "Please provide the two Microsoft Defender Device Inventory "
        "exports and the Microsoft Defender Antivirus Details report. "
        "The application automatically determines which Device "
        "Inventory export is Region A and which is Region B."
    )


    upload_col_1, upload_col_2, upload_col_3, button_col = (
        st.columns(
            [2, 2, 2, 1]
        )
    )


    with upload_col_1:

        inventory_file_1 = st.file_uploader(
            "Device Inventory 1",
            type=["csv"],
            accept_multiple_files=False,
            key="inventory_file_1",
            help=(
                "Upload either the Region A or Region B Microsoft Defender "
                "Device Inventory CSV. The region is detected "
                "automatically."
            )
        )


    with upload_col_2:

        inventory_file_2 = st.file_uploader(
            "Device Inventory 2",
            type=["csv"],
            accept_multiple_files=False,
            key="inventory_file_2",
            help=(
                "Upload the other Microsoft Defender Device Inventory "
                "CSV. The region is detected automatically."
            )
        )


    with upload_col_3:

        mdav_file = st.file_uploader(
            "Microsoft Defender Antivirus",
            type=["csv"],
            accept_multiple_files=False,
            key="mdav_file",
            help=(
                "Upload the Microsoft Defender Antivirus Details "
                "Export containing AV mode, security intelligence, "
                "engine, platform and scan health information."
            )
        )


    with button_col:

        st.write("")

        st.write("")


        run_button = st.button(
            "Run Analysis",
            type="primary",
            use_container_width=True,
            disabled=(
                inventory_file_1 is None
                or inventory_file_2 is None
                or mdav_file is None
            )
        )


    if run_button:

        try:

            with st.spinner(
                "Running CORP security analysis..."
            ):

                reports, summary = run_complete_analysis(
                    inventory_file_1,
                    inventory_file_2,
                    mdav_file
                )


                st.session_state["reports"] = reports

                st.session_state["summary"] = summary

                st.session_state["uploaded_file_names"] = [
                    inventory_file_1.name,
                    inventory_file_2.name,
                    mdav_file.name
                ]

                st.session_state["analysis_complete"] = True


            st.rerun()


        except Exception as error:

            st.session_state[
                "analysis_complete"
            ] = False


            st.error(
                f"Analysis failed: {error}"
            )


    if st.session_state["analysis_complete"]:

        st.success(
            "Analysis complete."
        )


        file_names = st.session_state[
            "uploaded_file_names"
        ]


        if file_names:

            st.caption(
                "Processed: "
                + " | ".join(
                    file_names
                )
            )


# --------------------------------------------------
# No results yet
# --------------------------------------------------

if not st.session_state["analysis_complete"]:

    st.info(
        "Upload all three required CSV reports above and select "
        "Run Analysis."
    )

    st.stop()


# --------------------------------------------------
# Results
# --------------------------------------------------

summary = st.session_state["summary"]

reports = st.session_state["reports"]


# --------------------------------------------------
# Onboarding Coverage
# --------------------------------------------------

st.header(
    "Onboarding Coverage"
)


coverage_row_1 = st.columns(4)


coverage_row_1[0].metric(
    "Total Devices Investigated",
    f"{summary['total_devices']:,}",
    help=(
        "Total unique devices identified across the Region A and Region B "
        "Device Inventory datasets after device-name deduplication."
    )
)


coverage_row_1[1].metric(
    "Overall Onboarding Coverage",
    f"{summary['onboarding_coverage']:.1f}%",
    help=(
        "Percentage of unique devices classified as Onboarded "
        "across the combined Region A and Region B inventory."
    )
)


coverage_row_1[2].metric(
    "Region A Devices Onboarded",
    f"{summary['region_a_onboarded']:,}",
    help=(
        "Unique devices with Onboarding Status equal to Onboarded "
        "in the Region A Device Inventory dataset."
    )
)


coverage_row_1[3].metric(
    "Region B Devices Onboarded",
    f"{summary['region_b_onboarded']:,}",
    help=(
        "Unique devices with Onboarding Status equal to Onboarded "
        "in the Region B Device Inventory dataset."
    )
)


coverage_row_2 = st.columns(2)


coverage_row_2[0].metric(
    "Region A Servers Onboarded",
    f"{summary['region_a_servers_onboarded']:,}",
    help=(
        "Unique Region A onboarded devices identified as servers through "
        "the Device Type or Device Category fields."
    )
)


coverage_row_2[1].metric(
    "Region B Servers Onboarded",
    f"{summary['region_b_servers_onboarded']:,}",
    help=(
        "Unique Region B onboarded devices identified as servers through "
        "the Device Type or Device Category fields."
    )
)


st.divider()


# --------------------------------------------------
# Onboarding Opportunities
# --------------------------------------------------

st.header(
    "Onboarding Opportunities"
)


onboarding_row = st.columns(4)


onboarding_row[0].metric(
    "Possible Candidates for Onboarding",
    f"{summary['possible_candidates']:,}",
    help=(
        "Devices that are not already onboarded and have useful "
        "evidence suggesting they may be valid CORP onboarding "
        "candidates through naming conventions, naming families "
        "or recognised domain evidence."
    )
)


onboarding_row[1].metric(
    "Possible Onboarding - Investigation Required",
    f"{summary['investigation_required']:,}",
    help=(
        "Devices showing as Can be onboarded that did not have "
        "sufficient naming or domain evidence to classify as a "
        "possible onboarding candidate automatically."
    )
)


onboarding_row[2].metric(
    "Unknown Devices Using CORP Internal IP",
    f"{summary['internal_ip_investigate']:,}",
    help=(
        "Investigation-required devices with at least one IPv4 "
        "address matching the CORP IPAM reference. Ambiguous "
        "192.168.x.x addresses are ignored."
    )
)


onboarding_row[3].metric(
    "False Can Be Onboarded Status",
    f"{summary['false_can_be_onboarded']:,}",
    help=(
        "Devices reported as Can be onboarded in the source data "
        "where the same normalised device name was found already "
        "onboarded elsewhere in the combined inventory."
    )
)


st.divider()


# --------------------------------------------------
# Device Health
# --------------------------------------------------

st.header(
    "Device Health"
)


health_row_1 = st.columns(4)


health_row_1[0].metric(
    "No Sensor Data - Region A",
    f"{summary['region_a_no_sensor']:,}",
    help=(
        "Region A devices with sensor-data issues identified from either "
        "Device Inventory telemetry or the Microsoft Defender "
        "Antivirus health dataset."
    )
)


health_row_1[1].metric(
    "No Sensor Data - Region B",
    f"{summary['region_b_no_sensor']:,}",
    help=(
        "Region B devices with sensor-data issues identified from either "
        "Device Inventory telemetry or the Microsoft Defender "
        "Antivirus health dataset."
    )
)


health_row_1[2].metric(
    "Unsupported - Region A",
    f"{summary['region_a_unsupported']:,}",
    help=(
        "Unique Region A devices whose onboarding status indicates "
        "that the device is unsupported."
    )
)


health_row_1[3].metric(
    "Unsupported - Region B",
    f"{summary['region_b_unsupported']:,}",
    help=(
        "Unique Region B devices whose onboarding status indicates "
        "that the device is unsupported."
    )
)


health_row_2 = st.columns(3)


health_row_2[0].metric(
    "Stale 31-60 Days",
    f"{summary['stale_31_60']:,}",
    help=(
        "Unique devices whose last recorded device update was "
        "between 31 and 60 days ago."
    )
)


health_row_2[1].metric(
    "Stale 61-90 Days",
    f"{summary['stale_61_90']:,}",
    help=(
        "Unique devices whose last recorded device update was "
        "between 61 and 90 days ago."
    )
)


health_row_2[2].metric(
    "Stale Over 90 Days",
    f"{summary['stale_over_90']:,}",
    help=(
        "Unique devices whose last recorded device update was "
        "more than 90 days ago."
    )
)


st.divider()


# --------------------------------------------------
# Operating System Estate
# --------------------------------------------------

st.header(
    "Operating System Estate"
)


os_row_1 = st.columns(4)


os_row_1[0].metric(
    "Windows 11",
    f"{summary['windows_11']:,}",
    help=(
        "Unique devices categorised as Windows 11 from the OS "
        "Platform and OS Version fields."
    )
)


os_row_1[1].metric(
    "Windows 10",
    f"{summary['windows_10']:,}",
    help=(
        "Unique devices categorised as Windows 10 from the OS "
        "Platform and OS Version fields."
    )
)


os_row_1[2].metric(
    "Windows Server",
    f"{summary['windows_server']:,}",
    help=(
        "Unique devices categorised as a Windows Server operating "
        "system."
    )
)


os_row_1[3].metric(
    "Legacy OS Devices",
    f"{summary['legacy_os']:,}",
    help=(
        "Devices matching the legacy operating-system rules in "
        "device_metrics.py, including explicitly configured older "
        "Windows desktop and Windows Server releases."
    )
)


os_row_2 = st.columns(2)


os_row_2[0].metric(
    "Linux",
    f"{summary['linux']:,}",
    help=(
        "Unique devices categorised as Linux from OS platform "
        "and version information."
    )
)


os_row_2[1].metric(
    "Other / Unknown OS",
    f"{summary['other_unknown_os']:,}",
    help=(
        "Unique devices that could not be classified into the "
        "configured Windows, Linux, macOS or mobile OS categories."
    )
)


st.divider()


# --------------------------------------------------
# Defender Antivirus Health
# --------------------------------------------------

st.header(
    "Microsoft Defender Antivirus Health"
)


defender_row_1 = st.columns(4)


defender_row_1[0].metric(
    "AV Reporting Devices",
    f"{summary['av_reporting_devices']:,}",
    help=(
        "Unique devices represented in the Microsoft Defender "
        "Antivirus Details dataset."
    )
)


defender_row_1[1].metric(
    "AV Active",
    f"{summary['av_active']:,}",
    help=(
        "Devices whose Microsoft Defender Antivirus mode is "
        "reported as Active."
    )
)


defender_row_1[2].metric(
    "AV Passive",
    f"{summary['av_passive']:,}",
    help=(
        "Devices whose Microsoft Defender Antivirus mode is "
        "reported as Passive."
    )
)


defender_row_1[3].metric(
    "EDR Blocked",
    f"{summary['edr_blocked']:,}",
    help=(
        "Devices whose AV mode in the MDAV report is reported "
        "as EDRBlocked."
    )
)


st.subheader(
    "Defender Signature Compliance"
)


signature_row = st.columns(4)


signature_row[0].metric(
    "Signature Compliance",
    f"{summary['signature_compliance_rate']:.1f}%",
    help=(
        "Signature compliance is calculated as devices whose "
        "Security intelligence up to date field is Yes divided "
        "by devices with an explicit Yes or No status. Devices "
        "with unknown or invalid telemetry are reported separately."
    )
)


signature_row[1].metric(
    "Signatures Up to Date",
    f"{summary['signature_compliant']:,}",
    help=(
        "Devices reporting Security intelligence up to date = Yes."
    )
)


signature_row[2].metric(
    "Signatures Non-Compliant",
    f"{summary['signature_non_compliant']:,}",
    help=(
        "Devices reporting Security intelligence up to date = No. "
        "The underlying device list can be exported from the "
        "Defender Signature Non-Compliant report."
    )
)


signature_row[3].metric(
    "Signature Status Unknown",
    f"{summary['signature_unknown']:,}",
    help=(
        "Devices where signature compliance cannot be determined "
        "because status or Defender security-intelligence telemetry "
        "is missing or invalid."
    )
)


st.subheader(
    "Defender Component Compliance"
)


component_row = st.columns(3)


component_row[0].metric(
    "Engine Compliance",
    f"{summary['engine_compliance_rate']:.1f}%",
    help=(
        "Compliance rate calculated from devices with an explicit "
        "Yes or No Engine up to date status."
    )
)


component_row[1].metric(
    "Platform Compliance",
    f"{summary['platform_compliance_rate']:.1f}%",
    help=(
        "Compliance rate calculated from devices with an explicit "
        "Yes or No Platform up to date status."
    )
)


component_row[2].metric(
    "Defender Telemetry Issues",
    f"{summary['telemetry_issues']:,}",
    help=(
        "Devices with missing or invalid Defender Antivirus "
        "telemetry, such as AV mode Other or missing/invalid "
        "security-intelligence, engine or platform version values."
    )
)


st.subheader(
    "Latest Observed Defender Versions"
)


version_row = st.columns(3)


version_row[0].metric(
    "Security Intelligence",
    summary[
        "latest_security_intel"
    ] or "No Data",
    help=(
        "Highest Security Intelligence version observed in the "
        "uploaded MDAV dataset. This is informational and is not "
        "used by itself to determine compliance."
    )
)


version_row[1].metric(
    "Defender Engine",
    summary[
        "latest_engine"
    ] or "No Data",
    help=(
        "Highest Defender Engine version observed in the uploaded "
        "MDAV dataset."
    )
)


version_row[2].metric(
    "Defender Platform",
    summary[
        "latest_platform"
    ] or "No Data",
    help=(
        "Highest Defender Platform version observed in the uploaded "
        "MDAV dataset."
    )
)


st.divider()


# --------------------------------------------------
# Report Viewer
# --------------------------------------------------

st.header(
    "Report Viewer"
)


report_names = list(
    REPORT_FILES.keys()
)


viewer_col_1, viewer_col_2 = st.columns(
    [3, 1]
)


with viewer_col_1:

    selected_report = st.selectbox(
        "Select report",
        options=report_names,
        index=0,
        help=(
            "Select any generated report to inspect the underlying "
            "device-level results."
        )
    )


dataframe = reports.get(
    selected_report,
    pd.DataFrame()
)


with viewer_col_2:

    st.metric(
        "Report Rows",
        f"{len(dataframe):,}",
        help=(
            "Number of rows contained in the currently selected "
            "report."
        )
    )


if not dataframe.empty:

    unique_devices = count_unique_devices(
        dataframe
    )


    st.caption(
        f"{unique_devices:,} unique devices in this report"
    )


# --------------------------------------------------
# Search
# --------------------------------------------------

search_text = st.text_input(
    "Search selected report",
    placeholder=(
        "Search device name, IP, domain, location, "
        "status, reason, version or any other field"
    ),
    help=(
        "Searches across every column in the selected report."
    )
)


filtered_dataframe = dataframe.copy()


if (
    not dataframe.empty
    and search_text.strip()
):

    search_mask = (
        filtered_dataframe
        .astype(str)
        .apply(
            lambda column:
                column.str.contains(
                    search_text,
                    case=False,
                    regex=False,
                    na=False
                )
        )
        .any(
            axis=1
        )
    )


    filtered_dataframe = (
        filtered_dataframe[
            search_mask
        ]
    )


# --------------------------------------------------
# CSV table
# --------------------------------------------------

if dataframe.empty:

    st.warning(
        "The selected report contains no records."
    )


else:

    st.caption(
        f"Showing {len(filtered_dataframe):,} "
        f"of {len(dataframe):,} rows"
    )


    st.dataframe(
        filtered_dataframe,
        use_container_width=True,
        height=600,
        hide_index=True
    )


# --------------------------------------------------
# Export
# --------------------------------------------------

download_col, clear_col, spacer_col = st.columns(
    [1, 1, 3]
)


with download_col:

    selected_file_name = (
        REPORT_FILES[
            selected_report
        ].name
    )


    st.download_button(
        label="Export Selected Report",
        data=dataframe_to_csv(
            filtered_dataframe
        ),
        file_name=selected_file_name,
        mime="text/csv",
        use_container_width=True,
        disabled=filtered_dataframe.empty,
        help=(
            "Downloads the currently displayed rows as a CSV. "
            "If a search filter is active, only the filtered rows "
            "are exported."
        )
    )


with clear_col:

    if st.button(
        "Clear Analysis",
        use_container_width=True,
        help=(
            "Clears the current dashboard results from the "
            "Streamlit session."
        )
    ):

        st.session_state[
            "analysis_complete"
        ] = False

        st.session_state[
            "reports"
        ] = {}

        st.session_state[
            "summary"
        ] = {}

        st.session_state[
            "uploaded_file_names"
        ] = []

        st.rerun()