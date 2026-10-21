import pandas as pd
from sklearn.model_selection import train_test_split

# 1. Load the preprocessed dataset
dataset_path = "final_dataset_pn.csv"
print(f"Loading dataset from {dataset_path}...")
df = pd.read_csv(dataset_path)

# 2. Separate features (X) and target label (y)
X = df.drop(columns=["Label"])
y = df["Label"]

# 3. Perform a 20% train-test split
# stratify=y preserves class proportions across all attack categories and benign traffic
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# 4. Save the test set matrices to CSV files
print("Saving test matrices...")
X_test.to_csv("X_test.csv", index=False)
y_test.to_csv("y_test.csv", index=False)

print(
    f"Successfully saved X_test.csv ({X_test.shape}) and y_test.csv ({y_test.shape})."
)