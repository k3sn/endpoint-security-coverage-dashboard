from pathlib import Path


# Find the folder where this config.py file is located
BASE_DIR = Path(__file__).resolve().parent


# Input folder location
INPUT_DIR = BASE_DIR / "input"


# Output folder location
OUTPUT_DIR = BASE_DIR / "output"


# Reference folder location
REFERENCE_DIR = BASE_DIR / "reference"