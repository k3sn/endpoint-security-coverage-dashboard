import csv
import re

from config import REFERENCE_DIR


NAMING_RULES_FILE = (
    REFERENCE_DIR / "CORP_naming_rules.csv"
)


def clean_csv_row(row):

    cleaned_row = {}

    for key, value in row.items():

        if key is None:
            continue

        clean_key = str(key).strip()

        if value is None:
            clean_value = ""
        else:
            clean_value = str(value).strip()

        cleaned_row[clean_key] = clean_value

    return cleaned_row


def load_naming_rules():

    if not NAMING_RULES_FILE.exists():

        raise FileNotFoundError(
            f"Naming rules file not found: "
            f"{NAMING_RULES_FILE}"
        )

    with open(
        NAMING_RULES_FILE,
        "r",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        reader = csv.DictReader(
            file,
            skipinitialspace=True
        )

        rows = [
            clean_csv_row(row)
            for row in reader
        ]

    if not rows:

        raise ValueError(
            "CORP naming rules file is empty."
        )

    enabled_rows = []

    for row in rows:

        enabled = (
            row.get(
                "Enabled",
                ""
            )
            .strip()
            .lower()
        )

        if enabled == "true":

            enabled_rows.append(row)

    if not enabled_rows:

        raise ValueError(
            "CORP naming rules file loaded, "
            "but no enabled rules were found."
        )

    return enabled_rows


def build_reference_data(rules):

    reference_data = {

        "site_codes": set(),

        "region_b_mine_sites": set(),

        "region_b_environment_codes": set(),

        "region_b_server_roles": set(),

        "general_server_roles": set(),

        "device_type_codes": set(),

        "official_formats": []
    }


    for rule in rules:

        category = (
            rule.get(
                "RuleCategory",
                ""
            )
            .strip()
        )

        rule_type = (
            rule.get(
                "RuleType",
                ""
            )
            .strip()
            .upper()
        )


        if category == "SiteCode":

            value = (
                rule.get(
                    "SiteCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "site_codes"
                ].add(value)


        elif category == "Region BMineSite":

            value = (
                rule.get(
                    "SiteCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "region_b_mine_sites"
                ].add(value)


        elif category == "EnvironmentCode":

            value = (
                rule.get(
                    "EnvironmentCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "region_b_environment_codes"
                ].add(value)


        elif category == "Region BServerRole":

            value = (
                rule.get(
                    "RoleCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "region_b_server_roles"
                ].add(value)


        elif category == "ServerRole":

            value = (
                rule.get(
                    "RoleCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "general_server_roles"
                ].add(value)


        elif category == "DeviceTypeCode":

            value = (
                rule.get(
                    "TypeCode",
                    ""
                )
                .strip()
                .upper()
            )

            if value:

                reference_data[
                    "device_type_codes"
                ].add(value)


        if (
            category == "NamingFormat"
            and rule_type == "OFFICIAL"
        ):

            reference_data[
                "official_formats"
            ].append(rule)


    return reference_data


def has_valid_characters(device_name):

    return bool(
        re.fullmatch(
            r"[A-Z0-9-]+",
            device_name
        )
    )


def empty_result(
    device_type,
    reason,
    standard="",
    rule_type="OFFICIAL",
    format_value=""
):

    return {

        "matched": False,

        "standard":
            standard,

        "rule_type":
            rule_type,

        "format":
            format_value,

        "device_type":
            device_type,

        "region": "",

        "site": "",

        "cluster": "",

        "environment": "",

        "role": "",

        "instance": "",

        "reason":
            reason
    }


def validate_workstation_name(
    device_name,
    reference_data
):

    for rule in reference_data[
        "official_formats"
    ]:

        applies_to = (
            rule.get(
                "AppliesTo",
                ""
            )
            .strip()
            .lower()
        )

        if applies_to != "workstation":
            continue


        regex_pattern = (
            rule.get(
                "RegexPattern",
                ""
            )
            .strip()
        )

        if not regex_pattern:
            continue


        if re.fullmatch(
            regex_pattern,
            device_name
        ):

            return {

                "matched": True,

                "standard":
                    rule.get(
                        "RuleName",
                        ""
                    ),

                "rule_type":
                    rule.get(
                        "RuleType",
                        ""
                    ),

                "format":
                    rule.get(
                        "Format",
                        ""
                    ),

                "device_type":
                    "Workstation",

                "region": "",

                "site": "",

                "cluster": "",

                "environment": "",

                "role": "",

                "instance": "",

                "reason":
                    "Official workstation naming rule matched"
            }


    return empty_result(
        "Workstation",
        "No official workstation naming rule matched"
    )


def validate_region_b_server_name(
    device_name,
    reference_data
):

    pattern = re.fullmatch(
        r"(AU)"
        r"([A-Z]{3})"
        r"([0-9])"
        r"([EI])"
        r"([A-Z0-9]{3})"
        r"([0-9]{2})",
        device_name
    )


    if not pattern:

        return empty_result(
            "Server",
            "Region B server structure did not match",
            "Region B Server Naming Standard",
            "OFFICIAL",
            "AABBBCDEEEFF"
        )


    region = pattern.group(1)

    site = pattern.group(2)

    cluster = pattern.group(3)

    environment = pattern.group(4)

    role = pattern.group(5)

    instance = pattern.group(6)


    result = {

        "matched": False,

        "standard":
            "Region B Server Naming Standard",

        "rule_type":
            "OFFICIAL",

        "format":
            "AABBBCDEEEFF",

        "device_type":
            "Server",

        "region":
            region,

        "site":
            site,

        "cluster":
            cluster,

        "environment":
            environment,

        "role":
            role,

        "instance":
            instance,

        "reason": ""
    }


    if (
        site not in
        reference_data[
            "region_b_mine_sites"
        ]
    ):

        result[
            "reason"
        ] = (
            "Region B mine site code is not recognised"
        )

        return result


    if (
        environment not in
        reference_data[
            "region_b_environment_codes"
        ]
    ):

        result[
            "reason"
        ] = (
            "Region B environment code is not recognised"
        )

        return result


    if (
        role not in
        reference_data[
            "region_b_server_roles"
        ]
    ):

        result[
            "reason"
        ] = (
            "Region B server role is not recognised"
        )

        return result


    result["matched"] = True

    result[
        "reason"
    ] = (
        "Official Region B server naming rule matched"
    )

    return result


def is_application_role(role):

    if len(role) <= 2:
        return False


    if role.endswith("DB"):

        application_code = role[:-2]

        if application_code.isalnum():
            return True


    if role.endswith("AP"):

        application_code = role[:-2]

        if application_code.isalnum():
            return True


    return False


def validate_general_server_name(
    device_name,
    reference_data
):

    pattern = re.fullmatch(
        r"([A-Z0-9]+)-"
        r"([A-Z0-9]+)-"
        r"([A-Z0-9]+)-"
        r"([0-9]{2})",
        device_name
    )


    if not pattern:

        return empty_result(
            "Server",
            "General server structure did not match",
            "General Server Naming Standard",
            "OFFICIAL",
            "[Site]-[Environment]-[Role]-[Number]"
        )


    site = pattern.group(1)

    environment = pattern.group(2)

    role = pattern.group(3)

    instance = pattern.group(4)


    result = {

        "matched": False,

        "standard":
            "General Server Naming Standard",

        "rule_type":
            "OFFICIAL",

        "format":
            "[Site]-[Environment]-[Role]-[Number]",

        "device_type":
            "Server",

        "region": "",

        "site":
            site,

        "cluster": "",

        "environment":
            environment,

        "role":
            role,

        "instance":
            instance,

        "reason": ""
    }


    if (
        site not in
        reference_data[
            "site_codes"
        ]
    ):

        result[
            "reason"
        ] = (
            "Server site code is not recognised"
        )

        return result


    role_is_valid = (
        role in
        reference_data[
            "general_server_roles"
        ]
    )


    if is_application_role(role):

        role_is_valid = True


    if not role_is_valid:

        result[
            "reason"
        ] = (
            "Server role code is not recognised"
        )

        return result


    result["matched"] = True

    result[
        "reason"
    ] = (
        "Official general server naming rule matched"
    )

    return result


def validate_device_name(
    device_name,
    device_type,
    reference_data
):

    normalised_name = (
        str(
            device_name
            if device_name is not None
            else ""
        )
        .strip()
        .upper()
    )


    normalised_type = (
        str(
            device_type
        )
        .strip()
        .lower()
    )


    if not normalised_name:

        return empty_result(
            normalised_type,
            "Device name is empty",
            rule_type=""
        )


    if not has_valid_characters(
        normalised_name
    ):

        return empty_result(
            normalised_type,
            (
                "Device name contains characters "
                "not allowed by the naming standard"
            )
        )


    if normalised_type == "workstation":

        return validate_workstation_name(
            normalised_name,
            reference_data
        )


    if normalised_type == "server":

        region_b_result = (
            validate_region_b_server_name(
                normalised_name,
                reference_data
            )
        )


        if region_b_result["matched"]:

            return region_b_result


        general_result = (
            validate_general_server_name(
                normalised_name,
                reference_data
            )
        )


        if general_result["matched"]:

            return general_result


        return empty_result(
            "Server",
            (
                f"Region B: {region_b_result['reason']} | "
                f"General: "
                f"{general_result['reason']}"
            )
        )


    return empty_result(
        normalised_type,
        (
            "Device type is not currently "
            "evaluated by onboarding coverage"
        ),
        rule_type=""
    )


def initialise_naming_rules():

    rules = load_naming_rules()

    reference_data = (
        build_reference_data(
            rules
        )
    )


    print()

    print(
        "CORP naming rules loaded."
    )

    print(
        f"Enabled rules loaded: "
        f"{len(rules)}"
    )

    print(
        f"Official naming formats: "
        f"{len(reference_data['official_formats'])}"
    )

    print(
        f"Site codes: "
        f"{len(reference_data['site_codes'])}"
    )

    print(
        f"Region B mine sites: "
        f"{len(reference_data['region_b_mine_sites'])}"
    )

    print(
        f"Region B environment codes: "
        f"{len(reference_data['region_b_environment_codes'])}"
    )

    print(
        f"Region B server roles: "
        f"{len(reference_data['region_b_server_roles'])}"
    )

    print(
        f"General server roles: "
        f"{len(reference_data['general_server_roles'])}"
    )


    return reference_data