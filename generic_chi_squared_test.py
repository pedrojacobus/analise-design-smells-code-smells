import pandas as pd
import scipy.stats as stats
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as stat


def chi_square_test_any_smell(merged_df):
    # Create binary columns indicating the presence of any design smell and any code smell
    merged_df["Any_Design_Smell"] = (
        merged_df[
            [
                "God_Class",
                "Complex_Class",
                "Large_Class",
                "Data_Class",
                "Feature_Envy",
                "Brain_Class",
            ]
        ]
        .any(axis=1)
        .astype(int)
    )
    code_smells_dummies = pd.get_dummies(
        merged_df["extra.metadata.vulnerability_class.0"], prefix="Code_Smell"
    )
    merged_df = pd.concat([merged_df, code_smells_dummies], axis=1)
    merged_df["Any_Code_Smell"] = code_smells_dummies.any(axis=1).astype(int)

    # Create a contingency table
    contingency_table = pd.crosstab(
        merged_df["Any_Design_Smell"], merged_df["Any_Code_Smell"]
    )

    # Perform Chi-Square Test
    chi2, p, dof, expected = stats.chi2_contingency(contingency_table)

    # Print results
    print("Contingency Table:")
    print(contingency_table)
    print("\nChi-Squared Test Result:")
    print(f"Chi2: {chi2}")
    print(f"p-value: {p}")
    print(f"Degrees of Freedom: {dof}")
    print(f"Expected Frequencies Table:")
    print(expected)
    print(f"\nSignificant: {'Yes' if p < 0.05 else 'No'}")

    # plot_chi_squared_distribution(chi2, dof)


def plot_chi_squared_distribution(chi2_statistic, dof):
    # Define the range for the x-axis
    x = np.linspace(0, chi2_statistic + 10, 500)

    # Compute the Chi-Squared distribution PDF
    y = stats.chi2.pdf(x, dof)

    # Plot the Chi-Squared distribution
    plt.figure(figsize=(10, 6))
    plt.plot(x, y, label=f"Chi-Squared Distribution (df={dof})", color="blue")

    # Plot the chi-squared test statistic
    plt.axvline(chi2_statistic, color="red", linestyle="dashed", linewidth=1)
    plt.text(
        chi2_statistic + 0.5, max(y) * 0.5, f"Chi2 = {chi2_statistic:.2f}", color="red"
    )

    # Add labels and title
    plt.xlabel("Chi-Squared Value")
    plt.ylabel("Probability Density")
    plt.title("Chi-Squared Distribution with Test Statistic")
    plt.legend()
    plt.grid(True)
    plt.show()
