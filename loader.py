import csv
import re

from config import INPUT_DIR
from config import OUTPUT_DIR


# --------------------------------------------------
# Input filename patterns
# --------------------------------------------------

DEVICE_FILE_PATTERN = re.compile(
    r"^devices \((\d+)\)\.csv$",
    re.IGNORECASE
)


MDAV_FILE_PATTERN = re.compile(
    r"^MDAV Details Export(?: \((\d+)\))?\.csv$",
    re.IGNORECASE
)


# --------------------------------------------------
# Clean headers
# --------------------------------------------------

def clean_headers(headers):

    cleaned_headers = []

    for header in headers:

        if header is None:
            cleaned_headers.append("")
            continue

        cleaned_headers.append(
            str(header).strip()
        )

    return cleaned_headers


# --------------------------------------------------
# Clean one CSV record
# --------------------------------------------------

def clean_record(record):

    cleaned_record = {}

    for key, value in record.items():

        if key is None:
            continue

        clean_key = str(key).strip()

        if value is None:
            clean_value = ""
        else:
            clean_value = str(value).strip()

        cleaned_record[
            clean_key
        ] = clean_value

    return cleaned_record


# --------------------------------------------------
# Find command-line input files
# --------------------------------------------------

def find_input_files():

    if not INPUT_DIR.exists():

        raise FileNotFoundError(
            f"Input directory not found: "
            f"{INPUT_DIR}"
        )


    device_files = []

    mdav_files = []


    for file in INPUT_DIR.iterdir():

        if not file.is_file():
            continue


        device_match = (
            DEVICE_FILE_PATTERN.match(
                file.name
            )
        )


        if device_match:

            device_files.append({
                "path":
                    file,

                "version":
                    int(
                        device_match.group(1)
                    )
            })

            continue


        mdav_match = (
            MDAV_FILE_PATTERN.match(
                file.name
            )
        )


        if mdav_match:

            version_value = (
                mdav_match.group(1)
            )


            if version_value:

                version = int(
                    version_value
                )

            else:

                version = 0


            mdav_files.append({
                "path":
                    file,

                "version":
                    version
            })


    # --------------------------------------------------
    # Exactly two Defender inventory exports
    # --------------------------------------------------

    if len(device_files) != 2:

        raise ValueError(
            f"Expected exactly 2 Defender "
            f"device exports, but found "
            f"{len(device_files)}."
        )


    device_files.sort(
        key=lambda item:
            item["version"]
    )


    # --------------------------------------------------
    # MDAV is optional for now
    #
    # This means existing workflows still run if
    # MDAV has not yet been added.
    # --------------------------------------------------

    mdav_file = None


    if mdav_files:

        # If multiple MDAV exports exist,
        # use the highest numbered export.
        mdav_files.sort(
            key=lambda item:
                item["version"]
        )


        mdav_file = (
            mdav_files[-1]["path"]
        )


    return {
        "device_files":
            device_files,

        "mdav_file":
            mdav_file
    }


# --------------------------------------------------
# Read physical CSV
# --------------------------------------------------

def read_csv_file(file_path):

    if not file_path.exists():

        raise FileNotFoundError(
            f"CSV file not found: "
            f"{file_path}"
        )


    if file_path.stat().st_size == 0:

        raise ValueError(
            f"{file_path.name} is empty."
        )


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


        headers = reader.fieldnames


        if not headers:

            raise ValueError(
                f"{file_path.name} "
                f"contains no headers."
            )


        headers = clean_headers(
            headers
        )


        rows = []


        for record in reader:

            rows.append(
                clean_record(
                    record
                )
            )


    if not rows:

        raise ValueError(
            f"{file_path.name} "
            f"contains no data rows."
        )


    return headers, rows


# --------------------------------------------------
# Read Streamlit upload
# --------------------------------------------------

def read_uploaded_csv(uploaded_file):

    if uploaded_file is None:

        raise ValueError(
            "No CSV file was uploaded."
        )


    uploaded_file.seek(0)


    raw_data = (
        uploaded_file.getvalue()
    )


    if not raw_data:

        raise ValueError(
            f"{uploaded_file.name} "
            f"is empty."
        )


    try:

        text = raw_data.decode(
            "utf-8-sig"
        )

    except UnicodeDecodeError:

        try:

            text = raw_data.decode(
                "cp1252"
            )

        except UnicodeDecodeError as error:

            raise ValueError(
                f"{uploaded_file.name} "
                f"could not be decoded."
            ) from error


    reader = csv.DictReader(
        text.splitlines(),
        skipinitialspace=True
    )


    headers = reader.fieldnames


    if not headers:

        raise ValueError(
            f"{uploaded_file.name} "
            f"contains no headers."
        )


    headers = clean_headers(
        headers
    )


    rows = []


    for record in reader:

        rows.append(
            clean_record(
                record
            )
        )


    if not rows:

        raise ValueError(
            f"{uploaded_file.name} "
            f"contains no data rows."
        )


    return headers, rows


# --------------------------------------------------
# Validate device-export headers
# --------------------------------------------------

def validate_matching_headers(
    headers_1,
    headers_2,
    file_name_1,
    file_name_2
):

    if headers_1 != headers_2:

        raise ValueError(
            "Defender device export headers "
            "do not match.\n"
            f"{file_name_1}: {headers_1}\n"
            f"{file_name_2}: {headers_2}"
        )


# --------------------------------------------------
# Detect Region A / Region B export
# --------------------------------------------------

def detect_export_region(rows):

    region_a_score = 0

    region_b_score = 0


    for record in rows:

        tags = str(
            record.get(
                "Tags",
                ""
            )
        ).lower()


        domain = str(
            record.get(
                "Domain",
                ""
            )
        ).lower()


        device_name = str(
            record.get(
                "Device Name",
                ""
            )
        ).lower()


        # Strong tag indicators

        if "region_a (providera)" in tags:
            region_a_score += 10


        if "region_b (providerb)" in tags:
            region_b_score += 10


        # Domain indicators

        if domain == "corp.example.local":
            region_a_score += 1


        if "corpregion_b" in domain:
            region_b_score += 2


        if "bwmregion_b" in domain:
            region_b_score += 2


        if "rgcregion_b" in domain:
            region_b_score += 2


        # Naming indicators

        if device_name.startswith(
            "rgaws"
        ):
            region_a_score += 1


        if device_name.startswith(
            "rga"
        ):
            region_b_score += 1


        if device_name.startswith(
            "rgb"
        ):
            region_b_score += 1


        if device_name.startswith(
            "rgc"
        ):
            region_b_score += 1


        if device_name.startswith(
            "ausit"
        ):
            region_b_score += 1


        if device_name.startswith(
            "aurgc"
        ):
            region_b_score += 1


    if region_a_score > region_b_score:

        region = "Region A"


    elif region_b_score > region_a_score:

        region = "Region B"


    else:

        region = "UNKNOWN"


    return {
        "region":
            region,

        "region_a_score":
            region_a_score,

        "region_b_score":
            region_b_score
    }


# --------------------------------------------------
# Identify the two regional exports
# --------------------------------------------------

def identify_regional_exports(
    rows_1,
    rows_2,
    file_name_1,
    file_name_2
):

    result_1 = detect_export_region(
        rows_1
    )


    result_2 = detect_export_region(
        rows_2
    )


    print()

    print(
        f"{file_name_1} detected as "
        f"{result_1['region']} "
        f"(Region A: {result_1['region_a_score']}, "
        f"Region B: {result_1['region_b_score']})"
    )


    print(
        f"{file_name_2} detected as "
        f"{result_2['region']} "
        f"(Region A: {result_2['region_a_score']}, "
        f"Region B: {result_2['region_b_score']})"
    )


    if (
        result_1["region"] == "UNKNOWN"
        or result_2["region"] == "UNKNOWN"
    ):

        raise ValueError(
            "Could not determine which "
            "Defender export is Region A and "
            "which is Region B."
        )


    if (
        result_1["region"]
        == result_2["region"]
    ):

        raise ValueError(
            "Both device exports were detected "
            f"as {result_1['region']}."
        )


    if result_1["region"] == "Region A":

        return {
            "region_a_rows":
                rows_1,

            "region_b_rows":
                rows_2,

            "region_a_file_name":
                file_name_1,

            "region_b_file_name":
                file_name_2
        }


    return {
        "region_a_rows":
            rows_2,

        "region_b_rows":
            rows_1,

        "region_a_file_name":
            file_name_2,

        "region_b_file_name":
            file_name_1
    }


# --------------------------------------------------
# Save generic CSV dataset
# --------------------------------------------------

def save_dataset(
    file_name,
    headers,
    records
):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    output_file = (
        OUTPUT_DIR
        / file_name
    )


    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=headers
        )


        writer.writeheader()


        writer.writerows(
            records
        )


    return output_file


# --------------------------------------------------
# Save regional/raw datasets
# --------------------------------------------------

def save_all_raw_datasets(
    headers,
    region_a_rows,
    region_b_rows
):

    combined_records = (
        region_a_rows
        + region_b_rows
    )


    combined_file = save_dataset(
        "combined_raw_dataset.csv",
        headers,
        combined_records
    )


    region_a_file = save_dataset(
        "region_a_raw_dataset.csv",
        headers,
        region_a_rows
    )


    region_b_file = save_dataset(
        "region_b_raw_dataset.csv",
        headers,
        region_b_rows
    )


    return {
        "combined_records":
            combined_records,

        "combined_file":
            combined_file,

        "region_a_file":
            region_a_file,

        "region_b_file":
            region_b_file
    }


# --------------------------------------------------
# Save MDAV dataset
# --------------------------------------------------

def save_mdav_dataset(
    headers,
    rows
):

    return save_dataset(
        "mdav_raw_dataset.csv",
        headers,
        rows
    )


# --------------------------------------------------
# Command-line loader
# --------------------------------------------------

def load_inputs():

    discovered_files = (
        find_input_files()
    )


    device_files = (
        discovered_files[
            "device_files"
        ]
    )


    mdav_file = (
        discovered_files[
            "mdav_file"
        ]
    )


    file_1 = (
        device_files[0]["path"]
    )


    file_2 = (
        device_files[1]["path"]
    )


    print(
        f"Found device export: "
        f"{file_1.name}"
    )


    print(
        f"Found device export: "
        f"{file_2.name}"
    )


    if mdav_file:

        print(
            f"Found MDAV export: "
            f"{mdav_file.name}"
        )


    else:

        print(
            "No MDAV Details Export found."
        )


    headers_1, rows_1 = (
        read_csv_file(
            file_1
        )
    )


    headers_2, rows_2 = (
        read_csv_file(
            file_2
        )
    )


    validate_matching_headers(
        headers_1,
        headers_2,
        file_1.name,
        file_2.name
    )


    regional_data = (
        identify_regional_exports(
            rows_1,
            rows_2,
            file_1.name,
            file_2.name
        )
    )


    output_results = (
        save_all_raw_datasets(
            headers_1,
            regional_data[
                "region_a_rows"
            ],
            regional_data[
                "region_b_rows"
            ]
        )
    )


    # --------------------------------------------------
    # MDAV health export
    # --------------------------------------------------

    if mdav_file:

        mdav_headers, mdav_rows = (
            read_csv_file(
                mdav_file
            )
        )


        mdav_output = (
            save_mdav_dataset(
                mdav_headers,
                mdav_rows
            )
        )


        print()

        print(
            f"MDAV rows loaded: "
            f"{len(mdav_rows)}"
        )


        print(
            f"MDAV raw dataset: "
            f"{mdav_output}"
        )


    print()

    print(
        f"Region A rows: "
        f"{len(regional_data['region_a_rows'])}"
    )


    print(
        f"Region B rows: "
        f"{len(regional_data['region_b_rows'])}"
    )


    print(
        f"Combined rows: "
        f"{len(output_results['combined_records'])}"
    )


    print()

    print(
        f"Combined dataset: "
        f"{output_results['combined_file']}"
    )


    print(
        f"Region A dataset: "
        f"{output_results['region_a_file']}"
    )


    print(
        f"Region B dataset: "
        f"{output_results['region_b_file']}"
    )


    return output_results[
        "combined_records"
    ]


# --------------------------------------------------
# Streamlit loader
#
# Third argument is optional for now so the current
# app remains compatible until we redesign it.
# --------------------------------------------------

def load_uploaded_inputs(
    uploaded_file_1,
    uploaded_file_2,
    uploaded_mdav_file=None
):

    if uploaded_file_1 is None:

        raise ValueError(
            "First Defender CSV "
            "has not been uploaded."
        )


    if uploaded_file_2 is None:

        raise ValueError(
            "Second Defender CSV "
            "has not been uploaded."
        )


    if (
        uploaded_file_1.name
        == uploaded_file_2.name
        and uploaded_file_1.getvalue()
        == uploaded_file_2.getvalue()
    ):

        raise ValueError(
            "The same Defender CSV "
            "was uploaded twice."
        )


    headers_1, rows_1 = (
        read_uploaded_csv(
            uploaded_file_1
        )
    )


    headers_2, rows_2 = (
        read_uploaded_csv(
            uploaded_file_2
        )
    )


    validate_matching_headers(
        headers_1,
        headers_2,
        uploaded_file_1.name,
        uploaded_file_2.name
    )


    regional_data = (
        identify_regional_exports(
            rows_1,
            rows_2,
            uploaded_file_1.name,
            uploaded_file_2.name
        )
    )


    output_results = (
        save_all_raw_datasets(
            headers_1,
            regional_data[
                "region_a_rows"
            ],
            regional_data[
                "region_b_rows"
            ]
        )
    )


    # --------------------------------------------------
    # Optional Streamlit MDAV upload
    # --------------------------------------------------

    if uploaded_mdav_file is not None:

        mdav_headers, mdav_rows = (
            read_uploaded_csv(
                uploaded_mdav_file
            )
        )


        mdav_output = (
            save_mdav_dataset(
                mdav_headers,
                mdav_rows
            )
        )


        print()

        print(
            f"MDAV upload: "
            f"{uploaded_mdav_file.name}"
        )


        print(
            f"MDAV rows loaded: "
            f"{len(mdav_rows)}"
        )


        print(
            f"MDAV raw dataset: "
            f"{mdav_output}"
        )


    print()

    print(
        f"Region A export detected: "
        f"{regional_data['region_a_file_name']}"
    )


    print(
        f"Region A rows loaded: "
        f"{len(regional_data['region_a_rows'])}"
    )


    print()

    print(
        f"Region B export detected: "
        f"{regional_data['region_b_file_name']}"
    )


    print(
        f"Region B rows loaded: "
        f"{len(regional_data['region_b_rows'])}"
    )


    print()

    print(
        f"Combined rows: "
        f"{len(output_results['combined_records'])}"
    )


    return output_results[
        "combined_records"
    ]