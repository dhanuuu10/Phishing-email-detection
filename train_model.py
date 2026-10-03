import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# Load dataset
data = pd.read_csv("dataset.csv")

# Remove empty rows
data = data.dropna(subset=["text", "label"])

# Input and target
X = data["text"]
y = data["label"]


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# Create machine-learning pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        stop_words="english"
    )),
    ("classifier", LogisticRegression(
        max_iter=1000
    ))
])


# Train the model
model.fit(X_train, y_train)


# Test the model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel training completed!")
print(f"Accuracy: {accuracy:.2f}")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

cm=confusion_matrix(y_test,predictions)
print("\nConfusion Matrix:")
print(cm)


# Save trained model
joblib.dump(model, "phishing_model.pkl")

print("\nModel saved as: phishing_model.pkl")