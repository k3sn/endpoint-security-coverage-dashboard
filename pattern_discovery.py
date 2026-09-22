import csv
import re
from collections import defaultdict

from config import OUTPUT_DIR


DEVICE_NAME_COLUMN = "Device Name"
ONBOARDING_STATUS_COLUMN = "Onboarding Status"
DEVICE_TYPE_COLUMN = "Device Type"


STRUCTURAL_PATTERN_OUTPUT = (
    OUTPUT_DIR / "discovered_naming_patterns.csv"
)

NAMING_FAMILY_OUTPUT = (
    OUTPUT_DIR / "discovered_naming_families.csv"
)


# --------------------------------------------------
# Exclusions
# --------------------------------------------------

EXCLUDED_NAME_CONTAINS = [
    "RALLYBAR",
    "TAPSCHED",

    # Future exclusion template:
    # "NEW-EXCLUSION",
]


GUID_PATTERN = re.compile(
    r"^[0-9A-F]{8}-"
    r"[0-9A-F]{4}-"
    r"[0-9A-F]{4}-"
    r"[0-9A-F]{4}-"
    r"[0-9A-F]{12}$"
)


LETTERS_AND_NUMBERS_PATTERN = re.compile(
    r"^([A-Z]+)([0-9]+)$"
)


# --------------------------------------------------
# Normalisation
# --------------------------------------------------

def normalise_onboarding_status(status):

    if status is None:
        return ""

    return str(status).strip().lower()


def normalise_device_type(device_type):

    if device_type is None:
        return ""

    return str(device_type).strip().lower()


def normalise_device_name(device_name):

    if device_name is None:
        return ""

    name = str(device_name).strip().upper()

    if not name:
        return ""

    name = "".join(
        character
        for character in name
        if character.isprintable()
    )

    # Remove domain suffix
    if "." in name:
        name = name.split(".", 1)[0]

    return name.strip()


# --------------------------------------------------
# Identifier detection
# --------------------------------------------------

def is_guid_identifier(device_name):

    return bool(
        GUID_PATTERN.fullmatch(device_name)
    )


def is_hex_identifier(device_name):

    compact_name = (
        device_name
        .replace("-", "")
        .replace("_", "")
    )

    if len(compact_name) < 24:
        return False

    return all(
        character in "0123456789ABCDEF"
        for character in compact_name
    )


def is_identifier(device_name):

    if is_guid_identifier(device_name):
        return True

    if is_hex_identifier(device_name):
        return True

    return False


# --------------------------------------------------
# Exclusions
# --------------------------------------------------

def get_exclusion_reason(device_name):

    if is_identifier(device_name):
        return "Identifier or hash"

    for excluded_value in EXCLUDED_NAME_CONTAINS:

        if excluded_value in device_name:
            return f"Contains {excluded_value}"

    return ""


# --------------------------------------------------
# Detailed structural pattern
# --------------------------------------------------

def create_structural_pattern(device_name):

    pattern = []

    for character in device_name:

        if character.isalpha():
            pattern.append("A")

        elif character.isdigit():
            pattern.append("9")

        else:
            pattern.append(character)

    return "".join(pattern)


# --------------------------------------------------
# General helper for a variable section
# --------------------------------------------------

def describe_section(section):

    if not section:
        return ""

    if section.isdigit():
        return "[NUMERIC]"

    if section.isalpha():
        return section

    if section.isalnum():
        return f"[ALPHANUMERIC:{len(section)}]"

    return f"[VARIABLE:{len(section)}]"


# --------------------------------------------------
# Workstation family discovery
# --------------------------------------------------

def create_workstation_family(device_name):

    # --------------------------------------------------
    # Letters + numeric suffix
    #
    # RGAWS1745   -> RGAWS[NUMERIC]
    # RGAWS995    -> RGAWS[NUMERIC]
    # RGA0007375 -> RGA[NUMERIC]
    # PCWX421    -> PCWX[NUMERIC]
    # --------------------------------------------------

    numeric_match = LETTERS_AND_NUMBERS_PATTERN.fullmatch(
        device_name
    )

    if numeric_match:

        prefix = numeric_match.group(1)

        return f"{prefix}[NUMERIC]"


    # --------------------------------------------------
    # Hyphenated workstation names
    #
    # N-F4DXWL3
    # N-C72V6H4
    #
    # become:
    #
    # N-[ALPHANUMERIC:7]
    #
    # CORP-CM8BGG4 becomes:
    #
    # CORP-[ALPHANUMERIC:7]
    # --------------------------------------------------

    if "-" in device_name:

        sections = device_name.split("-")

        family_sections = []

        for section in sections:

            family_sections.append(
                describe_section(section)
            )

        return "-".join(
            family_sections
        )


    # --------------------------------------------------
    # Remaining mixed workstation names
    # --------------------------------------------------

    return create_structural_pattern(
        device_name
    )


# --------------------------------------------------
# Server family discovery
# --------------------------------------------------

def create_server_family(device_name):

    # --------------------------------------------------
    # Hyphenated server naming conventions
    #
    # Examples:
    #
    # DC1-PRD-RD-11
    # DC1-PRD-AAD-03
    # DC2-PRD-RMS-02
    # DC1-PRD-SWND-04
    #
    # These belong to the broader convention:
    #
    # DC[NUMERIC]-PRD-[ROLE]-[NUMERIC]
    # --------------------------------------------------

    sections = device_name.split("-")

    if len(sections) == 4:

        first = sections[0]
        environment = sections[1]
        role = sections[2]
        sequence = sections[3]

        first_match = LETTERS_AND_NUMBERS_PATTERN.fullmatch(
            first
        )

        if (
            first_match
            and environment.isalpha()
            and role.isalpha()
            and sequence.isdigit()
        ):

            prefix = first_match.group(1)

            return (
                f"{prefix}[NUMERIC]-"
                f"{environment}-"
                f"[ROLE]-"
                f"[NUMERIC]"
            )


    # --------------------------------------------------
    # Other hyphenated servers
    #
    # Example:
    #
    # NTL-COR-DHCP-01
    # TAR-COR-SWND-01
    # VIC-COR-FS-01
    #
    # becomes:
    #
    # [SITE]-COR-[ROLE]-[NUMERIC]
    # --------------------------------------------------

    if len(sections) == 4:

        site = sections[0]
        environment = sections[1]
        role = sections[2]
        sequence = sections[3]

        if (
            site.isalpha()
            and environment.isalpha()
            and role.isalpha()
            and sequence.isdigit()
        ):

            return (
                f"[SITE]-"
                f"{environment}-"
                f"[ROLE]-"
                f"[NUMERIC]"
            )


    # --------------------------------------------------
    # Generic hyphenated server fallback
    # --------------------------------------------------

    if "-" in device_name:

        family_sections = []

        for section in sections:

            family_sections.append(
                describe_section(section)
            )

        return "-".join(
            family_sections
        )


    # --------------------------------------------------
    # Letters + numeric suffix
    #
    # DCRAP15
    # DCRAP20
    #
    # becomes:
    #
    # DCRAP[NUMERIC]
    # --------------------------------------------------

    numeric_match = LETTERS_AND_NUMBERS_PATTERN.fullmatch(
        device_name
    )

    if numeric_match:

        prefix = numeric_match.group(1)

        return f"{prefix}[NUMERIC]"


    # --------------------------------------------------
    # Known long server convention:
    #
    # AUSRV0EPWDC01
    # AUSRV0IPSHO01
    #
    # becomes:
    #
    # AUSRV[SERVER-VARIABLE]
    #
    # AUSIT0EPWDC01
    #
    # becomes:
    #
    # AUSIT[SERVER-VARIABLE]
    # --------------------------------------------------

    prefix_match = re.match(
        r"^([A-Z]{5})(?=.*[0-9]).+$",
        device_name
    )

    if prefix_match:

        prefix = prefix_match.group(1)

        return (
            f"{prefix}"
            f"[SERVER-VARIABLE]"
        )


    # --------------------------------------------------
    # Long SITEA server convention
    #
    # SITEAPRDHDC526
    # SITEAPRDRDB524
    # SITEAPRDCTP516
    #
    # becomes:
    #
    # SITEAPRD[ROLE][NUMERIC]
    # --------------------------------------------------

    mccchp_match = re.match(
        r"^(SITEAPRD)"
        r"([A-Z]+)"
        r"([0-9]+)$",
        device_name
    )

    if mccchp_match:

        prefix = mccchp_match.group(1)

        return (
            f"{prefix}"
            f"[ROLE]"
            f"[NUMERIC]"
        )


    # --------------------------------------------------
    # Long SITEBPRD server convention
    #
    # SITEBPRDADC512
    # SITEBPRDAPP620
    # SITEBPRDFMS603
    #
    # becomes:
    #
    # SITEBPRD[ROLE][NUMERIC]
    # --------------------------------------------------

    mccocw_match = re.match(
        r"^(SITEBPRD)"
        r"([A-Z]+)"
        r"([0-9]+)$",
        device_name
    )

    if mccocw_match:

        prefix = mccocw_match.group(1)

        return (
            f"{prefix}"
            f"[ROLE]"
            f"[NUMERIC]"
        )


    # --------------------------------------------------
    # VM server convention
    #
    # VMPRDAPPAUE01
    # VMPRDDBAUE01
    # VMPRDSQLAUE01
    #
    # becomes:
    #
    # VMPRD[ROLE]AUE[NUMERIC]
    # --------------------------------------------------

    vm_match = re.match(
        r"^(VM[A-Z]{3})"
        r"([A-Z]+)"
        r"(AUE|ASE)"
        r"([0-9]+)$",
        device_name
    )

    if vm_match:

        prefix = vm_match.group(1)

        region = vm_match.group(3)

        return (
            f"{prefix}"
            f"[ROLE]"
            f"{region}"
            f"[NUMERIC]"
        )


    # --------------------------------------------------
    # Alphabetic-only server name
    # --------------------------------------------------

    if device_name.isalpha():

        return device_name


    # --------------------------------------------------
    # Final server fallback
    # --------------------------------------------------

    return create_structural_pattern(
        device_name
    )


# --------------------------------------------------
# Select family logic depending on device type
# --------------------------------------------------

def create_naming_family(
    device_name,
    device_type
):

    if device_type == "server":

        return create_server_family(
            device_name
        )

    if device_type == "workstation":

        return create_workstation_family(
            device_name
        )

    return create_structural_pattern(
        device_name
    )


# --------------------------------------------------
# Statistics container
# --------------------------------------------------

def create_statistics():

    return {
        "total": 0,
        "servers": 0,
        "workstations": 0,
        "other_device_types": 0,
        "examples": [],
        "structural_patterns": set()
    }


# --------------------------------------------------
# Add device to grouped results
# --------------------------------------------------

def add_device_to_group(
    grouped_results,
    group_name,
    device_name,
    device_type,
    structural_pattern
):

    data = grouped_results[
        group_name
    ]


    data["total"] += 1


    if device_type == "server":

        data["servers"] += 1

    elif device_type == "workstation":

        data["workstations"] += 1

    else:

        data["other_device_types"] += 1


    data["structural_patterns"].add(
        structural_pattern
    )


    if (
        device_name not in data["examples"]
        and len(data["examples"]) < 5
    ):

        data["examples"].append(
            device_name
        )


# --------------------------------------------------
# Analyse onboarded devices
# --------------------------------------------------

def analyse_device_names(records):

    structural_patterns = defaultdict(
        create_statistics
    )

    naming_families = defaultdict(
        create_statistics
    )


    total_records = 0

    onboarded_records = 0

    non_onboarded_records = 0

    missing_device_names = 0

    excluded_identifiers = 0

    excluded_name_rules = 0

    eligible_onboarded_devices = 0


    for record in records:

        total_records += 1


        onboarding_status = (
            normalise_onboarding_status(
                record.get(
                    ONBOARDING_STATUS_COLUMN,
                    ""
                )
            )
        )


        # --------------------------------------------------
        # Only onboarded devices are allowed to teach
        # the naming convention discovery engine
        # --------------------------------------------------

        if onboarding_status != "onboarded":

            non_onboarded_records += 1

            continue


        onboarded_records += 1


        normalised_name = (
            normalise_device_name(
                record.get(
                    DEVICE_NAME_COLUMN,
                    ""
                )
            )
        )


        if not normalised_name:

            missing_device_names += 1

            continue


        exclusion_reason = (
            get_exclusion_reason(
                normalised_name
            )
        )


        if exclusion_reason == "Identifier or hash":

            excluded_identifiers += 1

            continue


        if exclusion_reason:

            excluded_name_rules += 1

            continue


        eligible_onboarded_devices += 1


        device_type = (
            normalise_device_type(
                record.get(
                    DEVICE_TYPE_COLUMN,
                    ""
                )
            )
        )


        structural_pattern = (
            create_structural_pattern(
                normalised_name
            )
        )


        naming_family = (
            create_naming_family(
                normalised_name,
                device_type
            )
        )


        add_device_to_group(
            structural_patterns,
            structural_pattern,
            normalised_name,
            device_type,
            structural_pattern
        )


        add_device_to_group(
            naming_families,
            naming_family,
            normalised_name,
            device_type,
            structural_pattern
        )


    return {
        "structural_patterns":
            structural_patterns,

        "naming_families":
            naming_families,

        "total_records":
            total_records,

        "onboarded_records":
            onboarded_records,

        "non_onboarded_records":
            non_onboarded_records,

        "missing_device_names":
            missing_device_names,

        "excluded_identifiers":
            excluded_identifiers,

        "excluded_name_rules":
            excluded_name_rules,

        "eligible_onboarded_devices":
            eligible_onboarded_devices
    }


# --------------------------------------------------
# Safe example retrieval
# --------------------------------------------------

def get_example(examples, index):

    if len(examples) > index:

        return examples[index]

    return ""


# --------------------------------------------------
# Write structural pattern report
# --------------------------------------------------

def write_structural_pattern_report(
    structural_patterns
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    fieldnames = [
        "Structural Pattern",
        "Onboarded Device Count",
        "Server Count",
        "Workstation Count",
        "Other Device Type Count",
        "Example 1",
        "Example 2",
        "Example 3",
        "Example 4",
        "Example 5"
    ]


    with open(
        STRUCTURAL_PATTERN_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:


        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )


        writer.writeheader()


        sorted_patterns = sorted(
            structural_patterns.items(),
            key=lambda item: (
                -item[1]["total"],
                item[0]
            )
        )


        for pattern, data in sorted_patterns:

            examples = data["examples"]


            writer.writerow({

                "Structural Pattern":
                    pattern,

                "Onboarded Device Count":
                    data["total"],

                "Server Count":
                    data["servers"],

                "Workstation Count":
                    data["workstations"],

                "Other Device Type Count":
                    data["other_device_types"],

                "Example 1":
                    get_example(
                        examples,
                        0
                    ),

                "Example 2":
                    get_example(
                        examples,
                        1
                    ),

                "Example 3":
                    get_example(
                        examples,
                        2
                    ),

                "Example 4":
                    get_example(
                        examples,
                        3
                    ),

                "Example 5":
                    get_example(
                        examples,
                        4
                    )
            })


# --------------------------------------------------
# Write naming family report
# --------------------------------------------------

def write_naming_family_report(
    naming_families
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    fieldnames = [
        "Naming Family",
        "Onboarded Device Count",
        "Structural Pattern Count",
        "Server Count",
        "Workstation Count",
        "Other Device Type Count",
        "Example 1",
        "Example 2",
        "Example 3",
        "Example 4",
        "Example 5"
    ]


    with open(
        NAMING_FAMILY_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:


        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )


        writer.writeheader()


        sorted_families = sorted(
            naming_families.items(),
            key=lambda item: (
                -item[1]["total"],
                item[0]
            )
        )


        for family, data in sorted_families:

            examples = data["examples"]


            writer.writerow({

                "Naming Family":
                    family,

                "Onboarded Device Count":
                    data["total"],

                "Structural Pattern Count":
                    len(
                        data[
                            "structural_patterns"
                        ]
                    ),

                "Server Count":
                    data["servers"],

                "Workstation Count":
                    data["workstations"],

                "Other Device Type Count":
                    data["other_device_types"],

                "Example 1":
                    get_example(
                        examples,
                        0
                    ),

                "Example 2":
                    get_example(
                        examples,
                        1
                    ),

                "Example 3":
                    get_example(
                        examples,
                        2
                    ),

                "Example 4":
                    get_example(
                        examples,
                        3
                    ),

                "Example 5":
                    get_example(
                        examples,
                        4
                    )
            })


# --------------------------------------------------
# Main
# --------------------------------------------------

def run_pattern_discovery(records):

    print()

    print(
        "Starting onboarded device naming discovery..."
    )


    analysis = analyse_device_names(
        records
    )


    write_structural_pattern_report(
        analysis[
            "structural_patterns"
        ]
    )


    write_naming_family_report(
        analysis[
            "naming_families"
        ]
    )


    structural_count = len(
        analysis[
            "structural_patterns"
        ]
    )


    family_count = len(
        analysis[
            "naming_families"
        ]
    )


    print()

    print(
        "Onboarded device naming discovery completed."
    )

    print()

    print(
        f"Total Defender records: "
        f"{analysis['total_records']}"
    )

    print(
        f"Onboarded records: "
        f"{analysis['onboarded_records']}"
    )

    print(
        f"Non-onboarded records ignored: "
        f"{analysis['non_onboarded_records']}"
    )

    print()

    print(
        f"Missing onboarded device names: "
        f"{analysis['missing_device_names']}"
    )

    print(
        f"Identifier/hash names excluded: "
        f"{analysis['excluded_identifiers']}"
    )

    print(
        f"Excluded naming groups: "
        f"{analysis['excluded_name_rules']}"
    )

    print()

    print(
        f"Eligible onboarded devices used: "
        f"{analysis['eligible_onboarded_devices']}"
    )

    print(
        f"Unique structural patterns: "
        f"{structural_count}"
    )

    print(
        f"Unique naming families: "
        f"{family_count}"
    )

    print()

    print(
        f"Structural pattern report: "
        f"{STRUCTURAL_PATTERN_OUTPUT}"
    )

    print(
        f"Naming family report: "
        f"{NAMING_FAMILY_OUTPUT}"
    )


    return analysis