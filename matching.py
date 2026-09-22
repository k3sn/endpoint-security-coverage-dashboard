import csv
import re
from collections import defaultdict

from config import OUTPUT_DIR

from naming_rules import validate_device_name

from pattern_discovery import (
    normalise_device_name,
    normalise_device_type,
    normalise_onboarding_status,
    get_exclusion_reason,
    create_naming_family
)


# --------------------------------------------------
# Defender columns
# --------------------------------------------------

DEVICE_ID_COLUMN = "Device ID"
DEVICE_NAME_COLUMN = "Device Name"
DEVICE_CATEGORY_COLUMN = "Device Category"
DEVICE_TYPE_COLUMN = "Device Type"
ONBOARDING_STATUS_COLUMN = "Onboarding Status"

OS_PLATFORM_COLUMN = "OS Platform"
OS_VERSION_COLUMN = "OS Version"

DOMAIN_COLUMN = "Domain"
AAD_DEVICE_ID_COLUMN = "AAD Device Id"

DEVICE_IPS_COLUMN = "Device IPs"

MANAGED_BY_COLUMN = "Managed By"
GROUP_COLUMN = "Group"

LAST_UPDATE_COLUMN = "Last device update"


# --------------------------------------------------
# Output files
# --------------------------------------------------

POSSIBLE_CANDIDATES_OUTPUT = (
    OUTPUT_DIR / "possible_onboarding_candidates.csv"
)

INVESTIGATION_REQUIRED_OUTPUT = (
    OUTPUT_DIR / "investigation_required.csv"
)

ALREADY_ONBOARDED_OUTPUT = (
    OUTPUT_DIR / "already_onboarded_devices.csv"
)

EXCLUDED_OUTPUT = (
    OUTPUT_DIR / "excluded_onboarding_candidates.csv"
)


# --------------------------------------------------
# Thresholds
# --------------------------------------------------

MIN_ONBOARDED_EVIDENCE = 1

MIN_CANDIDATE_FAMILY_COUNT = 2


# --------------------------------------------------
# Explicitly approved domains
# --------------------------------------------------

APPROVED_DOMAINS = {
    "ot-a.example.local",
    "ot-b.example.local",
    "scada.example.local",
    "plant.example.local"
}


# Domains that must NEVER be treated as evidence
IGNORED_DOMAINS = {
    "",
    "workgroup"
}


# --------------------------------------------------
# Family helpers
# --------------------------------------------------

def create_family_statistics():

    return {
        "total": 0,
        "examples": []
    }


def get_example(
    examples,
    index
):

    if len(examples) > index:
        return examples[index]

    return ""


# --------------------------------------------------
# Domain helpers
# --------------------------------------------------

def normalise_domain(
    domain
):

    if domain is None:
        return ""

    return (
        str(domain)
        .strip()
        .lower()
    )


def split_domains(
    domain_value
):

    domains = []

    normalised_value = normalise_domain(
        domain_value
    )


    if not normalised_value:
        return domains


    for domain in normalised_value.split(","):

        domain = domain.strip()


        if (
            domain
            and domain not in domains
        ):

            domains.append(
                domain
            )


    return domains


# --------------------------------------------------
# Meaningful naming family detection
#
# GOOD:
#
# AP[NUMERIC]
# SITEBAPPCSOBY[NUMERIC]
# SITEBAPPCHPCTV[NUMERIC]
# SITEA-[ALPHANUMERIC:3]-DC-[NUMERIC]
# [SITE]-AHS-[ROLE]-[NUMERIC]
#
# BAD:
#
# AAA
# AAAAAAAAAA
# 999A9A9
# 9AAAA99999
# AA9AAA99
#
# A meaningful family must contain a recognised
# placeholder AND retain useful literal information.
# --------------------------------------------------

def is_meaningful_naming_family(
    naming_family
):

    if not naming_family:
        return False


    has_placeholder = any(
        marker in naming_family
        for marker in (
            "[NUMERIC]",
            "[ALPHANUMERIC:",
            "[SERVER-VARIABLE]",
            "[VARIABLE:",
            "[SITE]",
            "[ROLE]"
        )
    )


    if not has_placeholder:
        return False


    literal_part = naming_family


    # Remove known fixed placeholders
    for marker in (
        "[NUMERIC]",
        "[SERVER-VARIABLE]",
        "[SITE]",
        "[ROLE]"
    ):

        literal_part = literal_part.replace(
            marker,
            ""
        )


    # Remove generated variable-length placeholders
    literal_part = re.sub(
        r"\[ALPHANUMERIC:[0-9]+\]",
        "",
        literal_part
    )


    literal_part = re.sub(
        r"\[VARIABLE:[0-9]+\]",
        "",
        literal_part
    )


    # Remove separators
    literal_part = (
        literal_part
        .replace("-", "")
        .replace("_", "")
        .strip()
    )


    # Must contain literal alphabetic information
    return any(
        character.isalpha()
        for character in literal_part
    )


# --------------------------------------------------
# Build onboarded hostname index
#
# Exact normalised hostname comparison across the
# complete combined dataset.
# --------------------------------------------------

def build_onboarded_name_index(
    records
):

    onboarded_names = defaultdict(list)


    for record in records:

        status = normalise_onboarding_status(
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            )
        )


        if status != "onboarded":
            continue


        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:
            continue


        onboarded_names[
            device_name
        ].append(
            record
        )


    return onboarded_names


# --------------------------------------------------
# Build domains observed on onboarded devices
#
# WORKGROUP is deliberately excluded.
# --------------------------------------------------

def build_onboarded_domain_index(
    records
):

    onboarded_domains = defaultdict(
        lambda: {
            "device_names": set()
        }
    )


    for record in records:

        status = normalise_onboarding_status(
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            )
        )


        if status != "onboarded":
            continue


        device_type = normalise_device_type(
            record.get(
                DEVICE_TYPE_COLUMN,
                ""
            )
        )


        if device_type not in (
            "server",
            "workstation"
        ):
            continue


        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:
            continue


        domains = split_domains(
            record.get(
                DOMAIN_COLUMN,
                ""
            )
        )


        for domain in domains:

            if domain in IGNORED_DOMAINS:
                continue


            onboarded_domains[
                domain
            ][
                "device_names"
            ].add(
                device_name
            )


    return onboarded_domains


# --------------------------------------------------
# Build meaningful naming families from onboarded
# devices.
#
# Duplicate normalised hostnames are counted once.
# --------------------------------------------------

def build_known_families(
    records
):

    known_families = defaultdict(
        create_family_statistics
    )

    seen_names = defaultdict(set)


    for record in records:

        status = normalise_onboarding_status(
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            )
        )


        if status != "onboarded":
            continue


        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:
            continue


        exclusion_reason = get_exclusion_reason(
            device_name
        )


        if exclusion_reason:
            continue


        device_type = normalise_device_type(
            record.get(
                DEVICE_TYPE_COLUMN,
                ""
            )
        )


        if device_type not in (
            "server",
            "workstation"
        ):
            continue


        naming_family = create_naming_family(
            device_name,
            device_type
        )


        if not is_meaningful_naming_family(
            naming_family
        ):
            continue


        family_key = (
            device_type,
            naming_family
        )


        if (
            device_name
            in seen_names[
                family_key
            ]
        ):
            continue


        seen_names[
            family_key
        ].add(
            device_name
        )


        family = known_families[
            family_key
        ]


        family[
            "total"
        ] += 1


        if len(
            family[
                "examples"
            ]
        ) < 5:

            family[
                "examples"
            ].append(
                device_name
            )


    return known_families


# --------------------------------------------------
# Build candidate-side family index
#
# This is SUPPORTING evidence.
#
# Meaningful Naming Family itself is now sufficient
# for possible-candidate classification, even when
# candidate family count is only one.
# --------------------------------------------------

def build_candidate_family_index(
    records,
    onboarded_name_index
):

    candidate_families = defaultdict(set)


    for record in records:

        status = normalise_onboarding_status(
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            )
        )


        if status != "can be onboarded":
            continue


        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:
            continue


        device_type = normalise_device_type(
            record.get(
                DEVICE_TYPE_COLUMN,
                ""
            )
        )


        if device_type not in (
            "server",
            "workstation"
        ):
            continue


        if (
            device_name
            in onboarded_name_index
        ):
            continue


        exclusion_reason = get_exclusion_reason(
            device_name
        )


        if exclusion_reason:
            continue


        naming_family = create_naming_family(
            device_name,
            device_type
        )


        if not is_meaningful_naming_family(
            naming_family
        ):
            continue


        family_key = (
            device_type,
            naming_family
        )


        candidate_families[
            family_key
        ].add(
            device_name
        )


    return candidate_families


# --------------------------------------------------
# Create base output row
# --------------------------------------------------

def create_device_output(
    record,
    device_name,
    device_type,
    naming_family
):

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
            device_name,

        "Device Category":
            record.get(
                DEVICE_CATEGORY_COLUMN,
                ""
            ),

        "Device Type":
            device_type,

        "Onboarding Status":
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            ),

        "Generated Naming Family":
            naming_family,

        "Meaningful Naming Family":
            is_meaningful_naming_family(
                naming_family
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

        "Domain":
            record.get(
                DOMAIN_COLUMN,
                ""
            ),

        "AAD Device Id":
            record.get(
                AAD_DEVICE_ID_COLUMN,
                ""
            ),

        "Device IPs":
            record.get(
                DEVICE_IPS_COLUMN,
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
            )
    }


# --------------------------------------------------
# Add official CORP naming evidence
# --------------------------------------------------

def add_official_result(
    output,
    result
):

    output.update({

        "Official Naming Match":
            bool(
                result.get(
                    "matched",
                    False
                )
            ),

        "Official Standard":
            result.get(
                "standard",
                ""
            ),

        "Official Format":
            result.get(
                "format",
                ""
            ),

        "Official Region":
            result.get(
                "region",
                ""
            ),

        "Official Site":
            result.get(
                "site",
                ""
            ),

        "Official Cluster":
            result.get(
                "cluster",
                ""
            ),

        "Official Environment":
            result.get(
                "environment",
                ""
            ),

        "Official Role":
            result.get(
                "role",
                ""
            ),

        "Official Instance":
            result.get(
                "instance",
                ""
            ),

        "Official Validation Reason":
            result.get(
                "reason",
                ""
            )
    })


# --------------------------------------------------
# Add onboarded-family evidence
# --------------------------------------------------

def add_onboarded_family_result(
    output,
    known_family
):

    if known_family:

        evidence_count = known_family[
            "total"
        ]

        examples = known_family[
            "examples"
        ]

    else:

        evidence_count = 0

        examples = []


    onboarded_match = (
        evidence_count
        >= MIN_ONBOARDED_EVIDENCE
    )


    output.update({

        "Onboarded Family Match":
            onboarded_match,

        "Onboarded Evidence Count":
            evidence_count,

        "Known Onboarded Example 1":
            get_example(
                examples,
                0
            ),

        "Known Onboarded Example 2":
            get_example(
                examples,
                1
            ),

        "Known Onboarded Example 3":
            get_example(
                examples,
                2
            ),

        "Known Onboarded Example 4":
            get_example(
                examples,
                3
            ),

        "Known Onboarded Example 5":
            get_example(
                examples,
                4
            )
    })


# --------------------------------------------------
# Add candidate-side family information
#
# Count >= 2 is useful additional evidence,
# but NOT required for final classification.
# --------------------------------------------------

def add_candidate_family_result(
    output,
    family_key,
    candidate_family_index
):

    candidate_names = sorted(
        candidate_family_index.get(
            family_key,
            set()
        )
    )


    candidate_count = len(
        candidate_names
    )


    meaningful_family = bool(
        output.get(
            "Meaningful Naming Family",
            False
        )
    )


    candidate_family_match = (
        meaningful_family
        and candidate_count
        >= MIN_CANDIDATE_FAMILY_COUNT
    )


    output.update({

        "Candidate Family Match":
            candidate_family_match,

        "Candidate Family Count":
            candidate_count,

        "Candidate Family Example 1":
            get_example(
                candidate_names,
                0
            ),

        "Candidate Family Example 2":
            get_example(
                candidate_names,
                1
            ),

        "Candidate Family Example 3":
            get_example(
                candidate_names,
                2
            ),

        "Candidate Family Example 4":
            get_example(
                candidate_names,
                3
            ),

        "Candidate Family Example 5":
            get_example(
                candidate_names,
                4
            )
    })


# --------------------------------------------------
# Domain evidence
#
# Evidence comes from:
#
# 1. Explicitly approved domains
#
# 2. Domains already observed on onboarded devices
#
# WORKGROUP is ignored.
# --------------------------------------------------

def add_domain_result(
    output,
    record,
    onboarded_domain_index
):

    candidate_domains = split_domains(
        record.get(
            DOMAIN_COLUMN,
            ""
        )
    )


    domain_match = False

    matched_domain = ""

    domain_match_source = ""

    evidence_count = 0

    examples = []


    for domain in candidate_domains:

        if domain in IGNORED_DOMAINS:
            continue


        # Explicitly approved domain
        if domain in APPROVED_DOMAINS:

            domain_match = True

            matched_domain = domain

            domain_match_source = (
                "Approved domain"
            )


            known_domain = (
                onboarded_domain_index.get(
                    domain
                )
            )


            if known_domain:

                domain_names = known_domain[
                    "device_names"
                ]

                evidence_count = len(
                    domain_names
                )

                examples = sorted(
                    domain_names
                )


            break


        # Domain observed among actual
        # onboarded devices
        known_domain = (
            onboarded_domain_index.get(
                domain
            )
        )


        if known_domain:

            domain_names = known_domain[
                "device_names"
            ]


            if domain_names:

                domain_match = True

                matched_domain = domain

                domain_match_source = (
                    "Domain observed among onboarded devices"
                )

                evidence_count = len(
                    domain_names
                )

                examples = sorted(
                    domain_names
                )

                break


    output.update({

        "Established Domain Match":
            domain_match,

        "Matched Established Domain":
            matched_domain,

        "Domain Match Source":
            domain_match_source,

        "Domain Evidence Count":
            evidence_count,

        "Known Domain Example 1":
            get_example(
                examples,
                0
            ),

        "Known Domain Example 2":
            get_example(
                examples,
                1
            ),

        "Known Domain Example 3":
            get_example(
                examples,
                2
            )
    })


# --------------------------------------------------
# Build classification reason
# --------------------------------------------------

def build_candidate_reason(
    official_match,
    onboarded_family_match,
    meaningful_family,
    candidate_family_match,
    domain_match
):

    reasons = []


    if official_match:

        reasons.append(
            "Official CORP naming standard"
        )


    if onboarded_family_match:

        reasons.append(
            "Naming family observed among onboarded devices"
        )


    if meaningful_family:

        reasons.append(
            "Meaningful generated naming family"
        )


    if candidate_family_match:

        reasons.append(
            "Repeated meaningful naming family among Can be onboarded devices"
        )


    if domain_match:

        reasons.append(
            "Recognised domain evidence"
        )


    if not reasons:

        return (
            "No approved naming, family, "
            "or recognised domain evidence"
        )


    return " + ".join(
        reasons
    )


# --------------------------------------------------
# Evaluate candidate records
# --------------------------------------------------

def match_candidates(
    records,
    reference_data,
    known_families,
    onboarded_name_index,
    candidate_family_index,
    onboarded_domain_index
):

    possible_candidates = []

    investigation_required = []

    already_onboarded = []

    excluded = []


    total_can_be_onboarded = 0

    ignored_device_types = 0

    missing_device_names = 0


    for record in records:

        status = normalise_onboarding_status(
            record.get(
                ONBOARDING_STATUS_COLUMN,
                ""
            )
        )


        if status != "can be onboarded":
            continue


        total_can_be_onboarded += 1


        device_name = normalise_device_name(
            record.get(
                DEVICE_NAME_COLUMN,
                ""
            )
        )


        if not device_name:

            missing_device_names += 1

            continue


        device_type = normalise_device_type(
            record.get(
                DEVICE_TYPE_COLUMN,
                ""
            )
        )


        if device_type not in (
            "server",
            "workstation"
        ):

            ignored_device_types += 1

            continue


        naming_family = create_naming_family(
            device_name,
            device_type
        )


        output = create_device_output(
            record,
            device_name,
            device_type,
            naming_family
        )


        # --------------------------------------------------
        # 1. Already onboarded anywhere?
        # --------------------------------------------------

        onboarded_matches = (
            onboarded_name_index.get(
                device_name,
                []
            )
        )


        if onboarded_matches:

            onboarded_example = (
                onboarded_matches[0]
            )


            output.update({

                "Onboarded Match Count":
                    len(
                        onboarded_matches
                    ),

                "Onboarded Device ID":
                    onboarded_example.get(
                        DEVICE_ID_COLUMN,
                        ""
                    ),

                "Onboarded Device Name":
                    onboarded_example.get(
                        DEVICE_NAME_COLUMN,
                        ""
                    ),

                "Onboarded AAD Device Id":
                    onboarded_example.get(
                        AAD_DEVICE_ID_COLUMN,
                        ""
                    ),

                "Onboarded Group":
                    onboarded_example.get(
                        GROUP_COLUMN,
                        ""
                    ),

                "Onboarded Managed By":
                    onboarded_example.get(
                        MANAGED_BY_COLUMN,
                        ""
                    ),

                "Onboarded Domain":
                    onboarded_example.get(
                        DOMAIN_COLUMN,
                        ""
                    ),

                "Onboarded Last Device Update":
                    onboarded_example.get(
                        LAST_UPDATE_COLUMN,
                        ""
                    ),

                "Final Classification":
                    "ALREADY ONBOARDED"
            })


            already_onboarded.append(
                output
            )

            continue


        # --------------------------------------------------
        # 2. Explicit exclusion?
        # --------------------------------------------------

        exclusion_reason = (
            get_exclusion_reason(
                device_name
            )
        )


        if exclusion_reason:

            output.update({

                "Exclusion Reason":
                    exclusion_reason,

                "Final Classification":
                    "EXCLUDED"
            })


            excluded.append(
                output
            )

            continue


        # --------------------------------------------------
        # 3. Official CORP naming evidence
        # --------------------------------------------------

        official_result = (
            validate_device_name(
                device_name,
                device_type,
                reference_data
            )
        )


        add_official_result(
            output,
            official_result
        )


        official_match = bool(
            output[
                "Official Naming Match"
            ]
        )


        # --------------------------------------------------
        # 4. Meaningful generated naming family
        #
        # IMPORTANT:
        #
        # This is now DIRECT evidence.
        #
        # Candidate count does NOT need to be >= 2.
        # --------------------------------------------------

        meaningful_family = bool(
            output[
                "Meaningful Naming Family"
            ]
        )


        # --------------------------------------------------
        # 5. Onboarded-family evidence
        # --------------------------------------------------

        family_key = (
            device_type,
            naming_family
        )


        known_family = (
            known_families.get(
                family_key
            )
        )


        add_onboarded_family_result(
            output,
            known_family
        )


        onboarded_family_match = bool(
            output[
                "Onboarded Family Match"
            ]
        )


        # --------------------------------------------------
        # 6. Candidate-family repetition evidence
        #
        # Supporting evidence only.
        # --------------------------------------------------

        add_candidate_family_result(
            output,
            family_key,
            candidate_family_index
        )


        candidate_family_match = bool(
            output[
                "Candidate Family Match"
            ]
        )


        # --------------------------------------------------
        # 7. Domain evidence
        # --------------------------------------------------

        add_domain_result(
            output,
            record,
            onboarded_domain_index
        )


        domain_match = bool(
            output[
                "Established Domain Match"
            ]
        )


        # --------------------------------------------------
        # 8. Human-readable reason
        # --------------------------------------------------

        output[
            "Candidate Reason"
        ] = build_candidate_reason(
            official_match,
            onboarded_family_match,
            meaningful_family,
            candidate_family_match,
            domain_match
        )


        # --------------------------------------------------
        # 9. Final classification
        #
        # ANY of these is sufficient:
        #
        # - official CORP match
        # - onboarded family match
        # - meaningful generated family
        # - repeated candidate family
        # - approved / onboarded domain
        # --------------------------------------------------

        if (
            official_match
            or onboarded_family_match
            or meaningful_family
            or candidate_family_match
            or domain_match
        ):

            output[
                "Final Classification"
            ] = (
                "POSSIBLE ONBOARDING CANDIDATE"
            )


            possible_candidates.append(
                output
            )


        else:

            output[
                "Final Classification"
            ] = (
                "INVESTIGATION REQUIRED"
            )


            investigation_required.append(
                output
            )


    return {

        "possible_candidates":
            possible_candidates,

        "investigation_required":
            investigation_required,

        "already_onboarded":
            already_onboarded,

        "excluded":
            excluded,

        "total_can_be_onboarded":
            total_can_be_onboarded,

        "ignored_device_types":
            ignored_device_types,

        "missing_device_names":
            missing_device_names
    }


# --------------------------------------------------
# Common report fields
# --------------------------------------------------

def get_common_fields():

    return [

        "Device ID",

        "Original Device Name",

        "Normalised Device Name",

        "Device Category",

        "Device Type",

        "Onboarding Status",

        "Generated Naming Family",

        "Meaningful Naming Family",

        "OS Platform",

        "OS Version",

        "Domain",

        "AAD Device Id",

        "Device IPs",

        "Managed By",

        "Group",

        "Last Device Update"
    ]


# --------------------------------------------------
# Evidence report fields
# --------------------------------------------------

def get_evidence_fields():

    return (
        get_common_fields()
        + [

            "Official Naming Match",

            "Official Standard",

            "Official Format",

            "Official Region",

            "Official Site",

            "Official Cluster",

            "Official Environment",

            "Official Role",

            "Official Instance",

            "Official Validation Reason",

            "Onboarded Family Match",

            "Onboarded Evidence Count",

            "Known Onboarded Example 1",

            "Known Onboarded Example 2",

            "Known Onboarded Example 3",

            "Known Onboarded Example 4",

            "Known Onboarded Example 5",

            "Candidate Family Match",

            "Candidate Family Count",

            "Candidate Family Example 1",

            "Candidate Family Example 2",

            "Candidate Family Example 3",

            "Candidate Family Example 4",

            "Candidate Family Example 5",

            "Established Domain Match",

            "Matched Established Domain",

            "Domain Match Source",

            "Domain Evidence Count",

            "Known Domain Example 1",

            "Known Domain Example 2",

            "Known Domain Example 3",

            "Candidate Reason",

            "Final Classification"
        ]
    )


# --------------------------------------------------
# Write evidence report
# --------------------------------------------------

def write_evidence_report(
    records,
    output_file
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    fieldnames = (
        get_evidence_fields()
    )


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


        sorted_records = sorted(
            records,
            key=lambda row: (

                -int(
                    bool(
                        row.get(
                            "Official Naming Match",
                            False
                        )
                    )
                ),

                -int(
                    bool(
                        row.get(
                            "Onboarded Family Match",
                            False
                        )
                    )
                ),

                -int(
                    bool(
                        row.get(
                            "Meaningful Naming Family",
                            False
                        )
                    )
                ),

                -row.get(
                    "Onboarded Evidence Count",
                    0
                ),

                -row.get(
                    "Candidate Family Count",
                    0
                ),

                -row.get(
                    "Domain Evidence Count",
                    0
                ),

                row.get(
                    "Generated Naming Family",
                    ""
                ),

                row.get(
                    "Normalised Device Name",
                    ""
                )
            )
        )


        writer.writerows(
            sorted_records
        )


# --------------------------------------------------
# Write already onboarded report
# --------------------------------------------------

def write_already_onboarded_report(
    records
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    fieldnames = (
        get_common_fields()
        + [

            "Onboarded Match Count",

            "Onboarded Device ID",

            "Onboarded Device Name",

            "Onboarded AAD Device Id",

            "Onboarded Group",

            "Onboarded Managed By",

            "Onboarded Domain",

            "Onboarded Last Device Update",

            "Final Classification"
        ]
    )


    with open(
        ALREADY_ONBOARDED_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )


        writer.writeheader()


        sorted_records = sorted(
            records,
            key=lambda row:
                row.get(
                    "Normalised Device Name",
                    ""
                )
        )


        writer.writerows(
            sorted_records
        )


# --------------------------------------------------
# Write exclusions
# --------------------------------------------------

def write_excluded_report(
    records
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    fieldnames = (
        get_common_fields()
        + [

            "Exclusion Reason",

            "Final Classification"
        ]
    )


    with open(
        EXCLUDED_OUTPUT,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )


        writer.writeheader()


        sorted_records = sorted(
            records,
            key=lambda row:
                row.get(
                    "Normalised Device Name",
                    ""
                )
        )


        writer.writerows(
            sorted_records
        )


# --------------------------------------------------
# Main matching function
# --------------------------------------------------

def run_matching(
    records,
    reference_data
):

    print()

    print(
        "Starting onboarding candidate matching..."
    )


    # Build all onboarded hostname evidence
    onboarded_name_index = (
        build_onboarded_name_index(
            records
        )
    )


    # Build onboarded domain evidence
    onboarded_domain_index = (
        build_onboarded_domain_index(
            records
        )
    )


    # Build meaningful onboarded families
    known_families = (
        build_known_families(
            records
        )
    )


    # Build candidate-side family evidence
    candidate_family_index = (
        build_candidate_family_index(
            records,
            onboarded_name_index
        )
    )


    # Evaluate candidates
    results = match_candidates(
        records,
        reference_data,
        known_families,
        onboarded_name_index,
        candidate_family_index,
        onboarded_domain_index
    )


    # Write possible candidates
    write_evidence_report(
        results[
            "possible_candidates"
        ],
        POSSIBLE_CANDIDATES_OUTPUT
    )


    # Write investigation required
    write_evidence_report(
        results[
            "investigation_required"
        ],
        INVESTIGATION_REQUIRED_OUTPUT
    )


    # Write already onboarded
    write_already_onboarded_report(
        results[
            "already_onboarded"
        ]
    )


    # Write exclusions
    write_excluded_report(
        results[
            "excluded"
        ]
    )


    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    print()

    print(
        "Onboarding candidate matching completed."
    )

    print()

    print(
        f"Unique onboarded device names: "
        f"{len(onboarded_name_index)}"
    )

    print(
        f"Meaningful onboarded naming families: "
        f"{len(known_families)}"
    )

    print(
        f"Meaningful candidate naming families: "
        f"{len(candidate_family_index)}"
    )

    print(
        f"Established onboarded domains: "
        f"{len(onboarded_domain_index)}"
    )

    print()

    print(
        f"Can be onboarded records found: "
        f"{results['total_can_be_onboarded']}"
    )

    print(
        f"Non-server/workstation records ignored: "
        f"{results['ignored_device_types']}"
    )

    print(
        f"Already onboarded elsewhere: "
        f"{len(results['already_onboarded'])}"
    )

    print(
        f"Possible onboarding candidates: "
        f"{len(results['possible_candidates'])}"
    )

    print(
        f"Investigation required: "
        f"{len(results['investigation_required'])}"
    )

    print(
        f"Excluded: "
        f"{len(results['excluded'])}"
    )

    print(
        f"Missing device names: "
        f"{results['missing_device_names']}"
    )

    print()

    print(
        f"Possible candidates report: "
        f"{POSSIBLE_CANDIDATES_OUTPUT}"
    )

    print(
        f"Investigation required report: "
        f"{INVESTIGATION_REQUIRED_OUTPUT}"
    )

    print(
        f"Already onboarded report: "
        f"{ALREADY_ONBOARDED_OUTPUT}"
    )

    print(
        f"Excluded report: "
        f"{EXCLUDED_OUTPUT}"
    )


    return results