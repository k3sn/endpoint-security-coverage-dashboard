import csv

from config import OUTPUT_DIR


Region A_RAW_DATASET = (
    OUTPUT_DIR
    / "region_a_raw_dataset.csv"
)

Region B_RAW_DATASET = (
    OUTPUT_DIR
    / "region_b_raw_dataset.csv"
)


ONBOARDING_STATUS_COLUMN = (
    "Onboarding Status"
)

DEVICE_NAME_COLUMN = (
    "Device Name"
)

DEVICE_TYPE_COLUMN = (
    "Device Type"
)

DEVICE_CATEGORY_COLUMN = (
    "Device Category"
)


def clean_value(value):

    if value is None:
        return ""

    return str(value).strip()


def normalise_device_name(
    device_name
):

    return clean_value(
        device_name
    ).upper()


def load_dataset(
    file_path
):

    if not file_path.exists():

        raise FileNotFoundError(
            f"Dataset not found: "
            f"{file_path}"
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


        if not reader.fieldnames:

            raise ValueError(
                f"{file_path.name} "
                f"contains no headers."
            )


        records = []


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


def is_server(
    record
):

    device_type = clean_value(
        record.get(
            DEVICE_TYPE_COLUMN,
            ""
        )
    ).lower()


    device_category = clean_value(
        record.get(
            DEVICE_CATEGORY_COLUMN,
            ""
        )
    ).lower()


    if "server" in device_type:
        return True


    if "server" in device_category:
        return True


    return False


def get_unique_onboarded_devices(
    records
):

    devices = {}


    for record in records:

        if not is_onboarded(
            record
        ):
            continue


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


        if normalised_name not in devices:

            devices[
                normalised_name
            ] = record


        else:

            existing_record = devices[
                normalised_name
            ]


            if (
                is_server(record)
                and not is_server(
                    existing_record
                )
            ):

                devices[
                    normalised_name
                ] = record


    return devices


def calculate_region_metrics(
    records
):

    onboarded_devices = (
        get_unique_onboarded_devices(
            records
        )
    )


    onboarded_servers = 0


    for record in (
        onboarded_devices.values()
    ):

        if is_server(
            record
        ):

            onboarded_servers += 1


    return {
        "onboarded_devices":
            len(
                onboarded_devices
            ),

        "onboarded_servers":
            onboarded_servers
    }


def run_onboarded_devices():

    print()

    print(
        "Starting onboarded device analysis..."
    )


    region_a_records = load_dataset(
        Region A_RAW_DATASET
    )


    region_b_records = load_dataset(
        Region B_RAW_DATASET
    )


    region_a_metrics = (
        calculate_region_metrics(
            region_a_records
        )
    )


    region_b_metrics = (
        calculate_region_metrics(
            region_b_records
        )
    )


    total_onboarded = (
        region_a_metrics[
            "onboarded_devices"
        ]
        +
        region_b_metrics[
            "onboarded_devices"
        ]
    )


    total_servers = (
        region_a_metrics[
            "onboarded_servers"
        ]
        +
        region_b_metrics[
            "onboarded_servers"
        ]
    )


    results = {

        "region_a_onboarded":
            region_a_metrics[
                "onboarded_devices"
            ],

        "region_a_servers_onboarded":
            region_a_metrics[
                "onboarded_servers"
            ],

        "region_b_onboarded":
            region_b_metrics[
                "onboarded_devices"
            ],

        "region_b_servers_onboarded":
            region_b_metrics[
                "onboarded_servers"
            ],

        "total_onboarded":
            total_onboarded,

        "total_servers_onboarded":
            total_servers
    }


    print()

    print(
        "Onboarded device analysis completed."
    )

    print()

    print(
        f"Region A devices onboarded: "
        f"{results['region_a_onboarded']}"
    )

    print(
        f"Region A servers onboarded: "
        f"{results['region_a_servers_onboarded']}"
    )

    print()

    print(
        f"Region B devices onboarded: "
        f"{results['region_b_onboarded']}"
    )

    print(
        f"Region B servers onboarded: "
        f"{results['region_b_servers_onboarded']}"
    )

    print()

    print(
        f"Total onboarded: "
        f"{results['total_onboarded']}"
    )

    print(
        f"Total servers onboarded: "
        f"{results['total_servers_onboarded']}"
    )


    return results


if __name__ == "__main__":

    run_onboarded_devices()