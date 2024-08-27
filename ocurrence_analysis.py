import pandas as pd
import scipy.stats as stats
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np


def analyze_occurrence(merged_df):

    vulnerability_counts = {}

    index = [
        "Active Debug Code",
        "Cookie Security",
        "Cross-Site Request Forgery (CSRF)",
        "Cross-Site-Scripting (XSS)",
        "Cryptographic Issues",
        "Hard-coded Secrets",
        "Improper Validation",
        "Insecure Hashing Algorithm",
        "Mishandled Sensitive Information",
        "Path Traversal",
        "SQL Injection",
        "XML Injection",
    ]

    design_smells = [
        "God_Class",
        "Complex_Class",
        "Large_Class",
        "Data_Class",
        "Feature_Envy",
        "Brain_Class",
    ]

    smell_counts = {}

    for column in design_smells:
        if not column.startswith("Unnamed"):
            # Filter the dataframe for rows where the design smell is present
            filtered_df = merged_df[merged_df[column] == 1]

            # Count Ocurrences of each design smell
            smell_count = filtered_df[column].sum()
            smell_counts[column] = smell_count
            counts = filtered_df["extra.metadata.vulnerability_class.0"].value_counts()

            vulnerability_counts[column] = counts

            vulnerability_counts_df = pd.DataFrame(
                vulnerability_counts, index=index
            ).fillna(0)

    # Convert the counts dictionary to a DataFrame
    counts_df = pd.DataFrame(
        list(smell_counts.items()), columns=["Design Smell", "Número de Ocorrências"]
    )

    # Calculate the total number of design smells
    total_smells = counts_df["Número de Ocorrências"].sum()

    print(counts_df)
    print(vulnerability_counts_df)

    return counts_df, vulnerability_counts_df
