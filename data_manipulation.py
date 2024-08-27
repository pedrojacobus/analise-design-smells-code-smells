import pandas as pd
import scipy.stats as stats
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np


def get_smells_result_manipulation(input_csv):
    df = pd.read_csv(input_csv, delimiter=";")
    df = df.dropna(how="all")

    segments = df["Name"].str.split(".")

    def get_correct_segments(name_parts):
        if len(name_parts) > 1 and name_parts[-2][0].isupper():
            return ".".join(name_parts[-3:-1])
        else:
            return ".".join(name_parts[-2:])

    df["Name"] = segments.apply(get_correct_segments)

    result_df = df.groupby("Name").max().reset_index()

    return result_df


def java_class_name_manipulation(df):

    segments = df["Name"].str.split(".")

    def get_correct_segments(name_parts):
        return ".".join(name_parts[-3:-1])

    df["Name"] = segments.apply(get_correct_segments)

    result_df = df.groupby("Name").max().reset_index()

    print(f"Java classes {result_df}")

    return result_df


def semgrep_result_manipulation(input_csv):
    df = pd.read_csv(input_csv, delimiter=";")

    df["path"] = df["path"].str.split(".").str[-2]
    path_list = df["path"].str.split("/")

    def join_segments(name_parts):
        if isinstance(name_parts, list) and len(name_parts) >= 2:
            return ".".join(name_parts[-2:])
        else:
            return str(name_parts) if pd.notna(name_parts) else ""

    df["path"] = path_list.apply(join_segments)
    df.rename(columns={"path": "Name"}, inplace=True)
    df_without_duplicates = df.drop_duplicates(subset="Name")

    return df, df_without_duplicates


def get_design_smells_related_to_vulnerabilities(df):
    rows_with_one = df[
        [
            "God_Class",
            "Complex_Class",
            "Large_Class",
            "Data_Class",
            "Feature_Envy",
            "Brain_Class",
        ]
    ].any(axis=1)

    # Filter the original DataFrame to get the rows with at least one design smell = 1
    df_with_design_smells = df[rows_with_one]

    # Return the filtered DataFrame and the sum of rows with any design smell = 1
    return df_with_design_smells, rows_with_one.sum()


def get_design_smells_not_related_to_vulnerabilities(df):
    rows_with_zero = df[
        [
            "God_Class",
            "Complex_Class",
            "Large_Class",
            "Data_Class",
            "Feature_Envy",
            "Brain_Class",
        ]
    ].any(axis=0)

    return rows_with_zero.sum()


def extract_mother_class_name(df):
    """
    Extracts the mother class name from a potentially nested class name.

    Args:
    - class_name (str): The full class name including any nested class parts.

    Returns:
    - str: The mother class name.
    """

    df["Name"] = df["Name"].str.split(".")

    return df["Name"]
