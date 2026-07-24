# Dataset Organization

This directory contains all datasets used in the Network Threat Cognition Framework (NTCF) project.

## Directory Structure

```text
data/
├── raw/
├── processed/
└── README.md
```

## Raw Dataset

The `raw/` directory stores the original NSL-KDD dataset.

These files must remain unchanged throughout the project.

## Processed Dataset

The `processed/` directory will store datasets generated after preprocessing and feature engineering.

## Machine Learning Pipeline

The dataset will be used as follows:

1. Load the raw NSL-KDD dataset.
2. Perform preprocessing.
3. Encode categorical features.
4. Select relevant features.
5. Split the dataset into training and testing sets.
6. Train machine learning models.
7. Evaluate model performance.