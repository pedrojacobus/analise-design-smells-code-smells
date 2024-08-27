import pandas as pd
import scipy.stats as stats
from scipy.stats import combine_pvalues
import matplotlib.pyplot as plt
import numpy as np


def chi_square_test_analysis(merged_df):
    code_smells_dummies = pd.get_dummies(
        merged_df["extra.metadata.vulnerability_class.0"], prefix="Code_Smell"
    )

    merged_df = pd.concat([merged_df, code_smells_dummies], axis=1)

    def chi_square_test(design_smell, code_smell):
        # Ensure there are both 0s and 1s for the design smell and code smell
        if (
            merged_df[design_smell].nunique() > 1
            and merged_df[code_smell].nunique() > 1
        ):
            contingency_table = pd.crosstab(
                merged_df[design_smell], merged_df[code_smell]
            )
            if contingency_table.shape == (2, 2):
                chi2, p, dof, ef = stats.chi2_contingency(contingency_table)
                return chi2, p
            else:
                print(
                    f"Invalid contingency table shape for {design_smell} and {code_smell}"
                )
                return None, None
        else:
            print(
                f"Skipping Chi-Square test for {design_smell} and {code_smell} due to insufficient data"
            )
            return None, None

    design_smells = [
        "God_Class",
        "Complex_Class",
        "Large_Class",
        "Data_Class",
        "Feature_Envy",
        "Brain_Class",
    ]

    code_smells = code_smells_dummies.columns.tolist()

    p_values = {}

    for ds in design_smells:
        results = []
        chi2_values = []
        p_values[ds] = []
        for cs in code_smells:
            chi2, p = chi_square_test(ds, cs)
            if chi2 is not None and p is not None:
                chi2_values.append((cs, chi2))
                p_values[ds].append(p)
                if p < 0.05:
                    results.append(
                        {
                            "Code Smell": cs,
                            "Chi2": chi2,
                            "p-value": p,
                            "Significant": "Yes",
                        }
                    )
                else:
                    results.append(
                        {
                            "Code Smell": cs,
                            "Chi2": chi2,
                            "p-value": p,
                            "Significant": "No",
                        }
                    )

        results_df = pd.DataFrame(results)
        print(f"Results for Design Smell: {ds}")
        print(results_df)
        print("\n")

    return p_values


def combine_p_values(p_values):
    """Combine p-values using Fisher's method."""
    p_values = np.array(p_values)

    # Debug: Print out p-values to identify any non-scalar values
    for i, p in enumerate(p_values):
        if not np.isscalar(p):
            print(f"Non-scalar p-value detected at index {i}: {p}")

    # Check if all p-values are scalars, not arrays
    if not all(np.isscalar(p) for p in p_values):
        raise ValueError("All p-values should be scalar values.")

    # Apply Fisher's method
    chi2_statistic = -2 * np.sum(np.log(p_values))
    combined_p_value = stats.chi2.sf(chi2_statistic, 2 * len(p_values))

    return combined_p_value
