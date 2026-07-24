import pandas as pd


def remove_missing_values(df):
    cleaned_df = df.dropna()
    return cleaned_df


def remove_duplicates(df):
    cleaned_df = df.drop_duplicates()
    return cleaned_df


def handle_invalid_values(df):
    cleaned_df = df[df["duration"] >= 0]
    return cleaned_df


def standardize_text(df):
    df = df.copy()
    df["protocol_type"] = df["protocol_type"].str.lower()
    df["service"] = df["service"].str.lower()
    df["flag"] = df["flag"].str.lower()
    return df


def split_features_target(df):
    X = df.drop(columns=["label"])
    y = df["label"]
    return X, y


def save_processed_data(df, output_path):
    df.to_csv(output_path, index=False)