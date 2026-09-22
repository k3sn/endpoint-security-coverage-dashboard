from loader import load_inputs
from naming_rules import initialise_naming_rules
from pattern_discovery import run_pattern_discovery
from matching import run_matching
from internal_network import run_internal_network


def main():

    combined_records = load_inputs()

    reference_data = initialise_naming_rules()

    run_pattern_discovery(
        combined_records
    )

    matching_results = run_matching(
        combined_records,
        reference_data
    )

    run_internal_network(
        matching_results[
            "investigation_required"
        ]
    )


if __name__ == "__main__":
    main()
