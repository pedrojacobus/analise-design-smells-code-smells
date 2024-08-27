import os
import pandas as pd


def find_java_files(directory):
    java_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))
    java_files_df = pd.DataFrame(java_files, columns=["Name"])
    print(java_files_df["Name"])
    return java_files_df, len(java_files)
