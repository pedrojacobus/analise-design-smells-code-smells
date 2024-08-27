import json
import csv


def get_nested_value(data, keys):
    """
    Retrieve the value from a nested dictionary given a list of keys.

    :param data: The dictionary to retrieve the value from.
    :param keys: A list of keys representing the path to the value.
    :return: The value from the nested dictionary or None if any key is not found.
    """
    counter = 0
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, None)
        elif isinstance(data, list) and key.isdigit():
            index = int(key)
            if 0 <= index < len(data):
                data = data[index]
            else:
                return None
        elif isinstance(data, list) and counter < len(data):
            return data[counter]
            counter = counter + 1
        else:
            return None
    return data.strip() if isinstance(data, str) else data


def json_to_csv(json_file, csv_file, fields, array_key):
    """
    Convert JSON to CSV.

    :param json_file: Path to the input JSON file.
    :param csv_file: Path to the output CSV file.
    :param fields: List of fields to include in the CSV.
                   Nested fields are represented in dot notation,
                   and array indices are specified as part of the field path.
    :param array_key: Key of the array in the JSON object.
    """
    try:
        # Load JSON data
        with open(json_file, "r") as jf:
            data = json.load(jf)

        # Extract the array from the JSON object using get_nested_value
        data_array = get_nested_value(data, array_key.split("."))

        # Check if the data_array is valid
        if not isinstance(data_array, list):
            raise ValueError(
                f"The key '{array_key}' does not point to a valid list in the JSON data."
            )

        # Open CSV file for writing
        with open(csv_file, "w", newline="") as cf:
            writer = csv.writer(cf)

            # Write header row with field names
            writer.writerow(fields)

            # Loop through each item in the array
            for item in data_array:
                # Create a list of values for each field
                row_values = [
                    str(get_nested_value(item, field.split("."))).strip()
                    for field in fields
                ]

                # Write the row to CSV
                writer.writerow(row_values)

        print(f"CSV file '{csv_file}' created successfully.")
    except Exception as e:
        print(f"Error: {e}")


def extract_scanned_to_csv(json_file, csv_file):
    try:
        # Load JSON data
        with open(json_file, "r") as jf:
            data = json.load(jf)

        # Extract the 'scanned' array from 'paths'
        scanned_values = data.get("paths", {}).get("scanned", [])

        # Open CSV file for writing
        with open(csv_file, "w", newline="") as cf:
            writer = csv.writer(cf)
            writer.writerow(["path"])  # Write header

            # Write each value from the 'scanned' array into the CSV file
            for value in scanned_values:
                writer.writerow([value])

        print(f"CSV file '{csv_file}' created successfully.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    # Specify the path to the JSON file
    json_file = "C:/Users/pedro/OneDrive/Documentos/Computacao/Faculdade/TCC/codigos/analise/jenkins/jenkins_output.json"

    # Specify the path to the output CSV file

    csv_file = "jenkins_results.csv"
    csv_scanned_file = "jenkins_scanned.csv"

    # Specify the fields to include in the CSV
    fields = [
        "path",
        "extra.metadata.source",
        "extra.metadata.cwe.0",
        "extra.metadata.owasp.0",
        "extra.metadata.references.0",
        "extra.metadata.vulnerability_class.0",
    ]  # Replace with your actual fields

    # Convert JSON to CSV
    json_to_csv(json_file, csv_file, fields, "results")
    extract_scanned_to_csv(json_file, csv_scanned_file)
