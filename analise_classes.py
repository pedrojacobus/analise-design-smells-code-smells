import pandas as pd
import scipy.stats as stats
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from utils import find_java_files
from ocurrence_analysis import analyze_occurrence
from correlation_analysis import analyze_correlation
from chi_squared_test_by_design_smell import chi_square_test_analysis, combine_p_values
from generic_chi_squared_test import chi_square_test_any_smell
from data_manipulation import (
    get_design_smells_not_related_to_vulnerabilities,
    get_design_smells_related_to_vulnerabilities,
    get_smells_result_manipulation,
    semgrep_result_manipulation,
    java_class_name_manipulation,
)


def data_analysis_visualization(get_smells_input_csv, semgrep_input_csv, scanned_files):
    get_smells_df = get_smells_result_manipulation(get_smells_input_csv)

    semgrep_df, semgrep_df_without_duplicates = semgrep_result_manipulation(
        semgrep_input_csv
    )

    scanned_df, _ = semgrep_result_manipulation(scanned_files)

    merged_scanned_df = pd.merge(scanned_df, get_smells_df, on="Name", how="inner")

    merged_design_code_smells = pd.merge(
        merged_scanned_df, semgrep_df_without_duplicates, on="Name", how="left"
    )

    number_of_classes = len(merged_scanned_df)

    flawed_classes, number_of_vulnerable_flawed_classes = (
        get_design_smells_related_to_vulnerabilities(merged_scanned_df)
    )

    code_smells_df = pd.merge(
        semgrep_df, flawed_classes.drop_duplicates(), on="Name", how="inner"
    )

    classes_code_smells_percentage = (
        len(semgrep_df_without_duplicates) / number_of_classes
    ) * 100

    flawed_classes_percentage = (
        number_of_vulnerable_flawed_classes / number_of_classes
    ) * 100

    vulnerable_flawed_classes_percentage = (len(code_smells_df) / len(semgrep_df)) * 100

    print(f"Classes vulneraveis: {classes_code_smells_percentage}%")
    print(
        f"Porcentagem de classes com design smells sobre o total de classes: {flawed_classes_percentage}%"
    )
    print(
        f"Porcentagem de vulnerabilidades em classes com Design Smell:  {vulnerable_flawed_classes_percentage}%"
    )

    print(f"Numero de classes: {number_of_classes}")

    design_count, code_count = analyze_occurrence(merged_design_code_smells)

    chi_squared_result_p_values = chi_square_test_analysis(merged_design_code_smells)

    return (
        design_count,
        code_count,
        classes_code_smells_percentage,
        flawed_classes_percentage,
        vulnerable_flawed_classes_percentage,
        number_of_classes,
        len(semgrep_df),
        chi_squared_result_p_values,  # Return p-values dictionary
    )


def plot_graphs(
    design_smell_analysis, partial_code_smell_df, class_counter, code_smell_counter
):
    # Ensure partial_code_smell_df is sorted correctly
    partial_code_smell_df_sorted = partial_code_smell_df.sort_index(ascending=False)

    # Plot for Design Smells
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(
        x=design_smell_analysis["Design Smell"],
        y=design_smell_analysis["Número de Ocorrências"],
        palette="viridis",
    )
    plt.xlabel("Design Smells")
    plt.ylabel("Number of Occurrences")
    plt.title("Total Occurrences of Design Smells")
    plt.xticks(rotation=45)

    # Add values on top of the bars
    for p in ax.patches:
        ax.annotate(
            format(p.get_height(), ".1f"),
            (p.get_x() + p.get_width() / 2.0, p.get_height()),
            ha="center",
            va="center",
            xytext=(0, 10),
            textcoords="offset points",
        )

    plt.show()

    # Plot for Code Smells
    plt.figure(figsize=(10, 6))

    # Calculate means for each column in partial_code_smell_df_sorted
    mean_values = partial_code_smell_df_sorted.mean()

    # Ensure mean_values is a Series
    if not isinstance(mean_values, pd.Series):
        raise ValueError("Mean values should be a pandas Series.")

    ax = sns.barplot(
        x=mean_values.index,
        y=mean_values.values,
        palette="viridis",
    )
    plt.xlabel("Code Smells")
    plt.ylabel("Mean Number of Occurrences")
    plt.title("Mean Occurrences of Code Smells Across Projects")
    plt.xticks(rotation=45)

    # Add values on top of the bars
    for p in ax.patches:
        ax.annotate(
            format(p.get_height(), ".1f"),
            (p.get_x() + p.get_width() / 2.0, p.get_height()),
            ha="center",
            va="center",
            xytext=(0, 10),
            textcoords="offset points",
        )

    plt.show()

    # Plot for Percentages
    percentages_df = pd.DataFrame(
        {
            "Category": ["Total Classes", "Total Code Smells"],
            "Percentage": [class_counter, code_smell_counter],
        }
    )
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(
        x=percentages_df["Category"], y=percentages_df["Percentage"], palette="viridis"
    )
    plt.xlabel("Category")
    plt.ylabel("Count")
    plt.title("Total Number of Classes and Code Smells")
    plt.xticks(rotation=45)

    # Add values on top of the bars
    for p in ax.patches:
        ax.annotate(
            format(p.get_height(), ".1f"),
            (p.get_x() + p.get_width() / 2.0, p.get_height()),
            ha="center",
            va="center",
            xytext=(0, 10),
            textcoords="offset points",
        )

    plt.show()


def print_design_smell_counts_for_each_project(design_smell_analysis, project_name):
    print(f"Design Smell Counts for {project_name}:")
    for index, row in design_smell_analysis.iterrows():
        print(f"{row['Design Smell']}: {row['Número de Ocorrências']}")
    print("\n")


def main():

    dictionary_list = []

    tomcat_dict = {
        "get_smells_input_csv": "tomcat/tomcat9.csv",
        "semgrep_input_csv": "tomcat/tomcat_results_9.csv",
        "scanned_files": "tomcat/tomcat_scanned.csv",
    }

    cxf_dict = {
        "get_smells_input_csv": "cxf/cxf402.csv",
        "semgrep_input_csv": "cxf/cxf402_results.csv",
        "scanned_files": "C:cxf/cxf_scanned.csv",
    }

    spring_dict = {
        "get_smells_input_csv": "spring-framework/spring.csv",
        "semgrep_input_csv": "spring-framework/spring_results.csv",
        "scanned_files": "spring-framework/spring_scanned.csv",
    }

    kafka_dict = {
        "get_smells_input_csv": "kafka/kafka.csv",
        "semgrep_input_csv": "kafka/kafka_results.csv",
        "scanned_files": "kafka/kafka_scanned.csv",
    }

    solr_dict = {
        "get_smells_input_csv": "solr/solr.csv",
        "semgrep_input_csv": "solr/solr_results.csv",
        "scanned_files": "solr/solr_scanned.csv",
    }

    junit_dict = {
        "get_smells_input_csv": "junit/junit.csv",
        "semgrep_input_csv": "junit/junit_results.csv",
        "scanned_files": "junit/junit_scanned.csv",
    }

    jenkins_dict = {
        "get_smells_input_csv": "jenkins/jenkins.csv",
        "semgrep_input_csv": "jenkins/jenkins_results.csv",
        "scanned_files": "jenkins/jenkins_scanned.csv",
    }

    dictionary_list.append(tomcat_dict)
    dictionary_list.append(cxf_dict)
    dictionary_list.append(spring_dict)
    dictionary_list.append(kafka_dict)
    dictionary_list.append(solr_dict)
    dictionary_list.append(jenkins_dict)

    design_smell_analysis = pd.DataFrame(
        columns=["Design Smell", "Número de Ocorrências"]
    )
    design_smell_analysis["Design Smell"] = [
        "God_Class",
        "Complex_Class",
        "Large_Class",
        "Data_Class",
        "Feature_Envy",
        "Brain_Class",
    ]
    design_smell_analysis = design_smell_analysis.fillna(0)

    vulnerable_classes_percentage = 0
    flawed_classes_percentage = 0
    vulnerable_flawed_classes_percentage = 0
    partial_code_smell_df = pd.DataFrame()
    counter = 0
    class_counter = 0
    code_smell_counter = 0

    design_smells = [
        "God_Class",
        "Complex_Class",
        "Large_Class",
        "Data_Class",
        "Feature_Envy",
        "Brain_Class",
    ]

    all_p_values = {}
    project_names = ["Tomcat", "CXF", "Spring", "Kafka", "Solr", "Jenkins"]
    design_smell_analysis_list = []

    for idx, dictionary in enumerate(dictionary_list):
        # Call the data_analysis_visualization function
        (
            analysis_df,
            code_smell_df,
            individual_vulnerable_classes_percentage,
            individual_flawed_classes_percentage,
            individual_vulnerable_flawed_classes_percentage,
            number_of_classes,
            number_of_code_smells,
            chi_squared_result_p_values,
        ) = data_analysis_visualization(
            dictionary["get_smells_input_csv"],
            dictionary["semgrep_input_csv"],
            dictionary["scanned_files"],
        )
        for cs_ds_pair, p_val in chi_squared_result_p_values.items():
            if cs_ds_pair not in all_p_values:
                all_p_values[cs_ds_pair] = []
            all_p_values[cs_ds_pair].append(p_val)

        # Store the analysis_df for this project
        design_smell_analysis_list.append(analysis_df)

        # Print the design smell counts for this project
        print_design_smell_counts_for_each_project(analysis_df, project_names[idx])

        class_counter = class_counter + number_of_classes
        code_smell_counter = code_smell_counter + number_of_code_smells

        if counter == 0:
            partial_code_smell_df = code_smell_df
            counter = counter + 1
        else:
            partial_code_smell_df = partial_code_smell_df + code_smell_df
        design_smell_analysis[["Número de Ocorrências"]] = (
            analysis_df[["Número de Ocorrências"]]
            + design_smell_analysis[["Número de Ocorrências"]]
        )
        column_sums = partial_code_smell_df.sum()
        vulnerable_classes_percentage = (
            vulnerable_classes_percentage + individual_vulnerable_classes_percentage
        )

        flawed_classes_percentage = (
            flawed_classes_percentage + individual_flawed_classes_percentage
        )
        vulnerable_flawed_classes_percentage = (
            vulnerable_flawed_classes_percentage
            + individual_vulnerable_flawed_classes_percentage
        )

    print(
        f"Percentual medio de classes vulneráveis: {vulnerable_classes_percentage/len(dictionary_list)}"
    )
    print(
        f"Percentual medio de classes com design smells: {flawed_classes_percentage/len(dictionary_list)}"
    )
    print(
        f"Percentual medio de classes vulneráveis com design smells: {vulnerable_flawed_classes_percentage/len(dictionary_list)}"
    )
    design_smell_analysis[["Número de Ocorrências"]] = design_smell_analysis[
        ["Número de Ocorrências"]
    ]
    partial_code_smell_df = partial_code_smell_df
    print(f"Design Smell Analysis {design_smell_analysis}")
    print(f"Code Smell Analysis {partial_code_smell_df}")
    print(f"Number of Classes Analyzed {class_counter}")
    print(f"Total Number of Code Smells {code_smell_counter}")
    plot_graphs(
        design_smell_analysis, partial_code_smell_df, class_counter, code_smell_counter
    )


if __name__ == "__main__":
    main()
