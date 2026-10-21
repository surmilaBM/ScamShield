# ScamShield

**An ML-powered web application for identifying potentially suspicious messages and URLs.**

ScamShield combines machine-learning-based message analysis with rule-based URL screening to help users recognize warning signs commonly associated with online scams and phishing attempts.

## Features

- **Message Analyzer:** Analyzes message text using a trained machine learning model to identify potentially suspicious content.
- **URL Scanner:** Examines URL characteristics for possible warning signs, including the use of HTTP, IP-address hosts, and suspicious-looking URL paths.
- **Dashboard:** Displays scan statistics and a summary of recent activity.
- **Scan History:** Brings message and URL scan records together so users can review previous analyses.
- **Threat Insights:** Summarizes warning signals and patterns found in saved scan records.
- **Machine Learning Evaluation:** Includes model-training and evaluation scripts to help assess classifier performance.

## How It Works

### Message Analysis

ScamShield uses a trained text-classification model to analyze message content and classify it according to the application's configured categories.

The model is trained using text features extracted with TF-IDF and a Support Vector Machine (SVM) classifier. Probability calibration is used in the training pipeline to support confidence-related outputs where configured.

### URL Scanning

The URL scanner checks structural characteristics of a submitted URL and assigns a heuristic risk score based on detected indicators.

Examples of indicators include:

- Use of unencrypted HTTP.
- IP addresses used as the hostname.
- URL paths containing potentially suspicious terms.

The score represents detected warning signs, not a verified maliciousness verdict. The scanner does not independently establish whether a website is live, safe, or malicious.

### Dashboard and Scan History

The dashboard summarizes saved scan activity, while Scan History combines message and URL scan records. Threat Insights provides an overview of selected warning patterns found in those records.

## Technology Stack

- **Language:** Python
- **Web Framework:** Flask
- **Machine Learning:** scikit-learn
- **Text Feature Extraction:** TF-IDF
- **Model Persistence:** Joblib
- **Data Processing:** pandas
- **Visualization:** Matplotlib
- **Database:** SQLite
- **Frontend:** HTML, CSS, JavaScript

## Project Structure

```text
ScamShield/
├── app.py
├── train_model.py
├── experiments.py
├── test_consistency.py
├── requirements.txt
├── metrics.json
├── scam_model.joblib
├── vectorizer.joblib
├── data/
├── outputs/
├── static/
├── templates/
├── LICENSE
└── README.md
```

The project may also contain local files and folders that are intentionally excluded from version control, such as the SQLite database and Python virtual environment.

## Getting Started

### Prerequisites

- Python installed on your system.
- Git, if you want to clone the repository.

### 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ScamShield
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with your actual repository URL after creating the GitHub repository.

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

Open the local address printed in the terminal by Flask, commonly `http://127.0.0.1:5000/`.

**Note:** The application requires its trained model artifacts to be available at the paths expected by `app.py`. If those artifacts are not included in the repository, follow the project's model-training workflow before starting the application.

## Model Training and Evaluation

The repository includes `train_model.py` for training and evaluating the message-classification model. The script uses TF-IDF text features and a calibrated Linear Support Vector Classifier.

Training datasets and generated outputs should be handled according to the project's actual data files and configuration. Review `train_model.py` for the expected dataset paths before running it.

## Scope and Considerations

ScamShield is intended as a supporting tool for identifying potentially suspicious content.

- URL risk scores are based on structural indicators and do not confirm whether a website is malicious.
- A low-risk result does not guarantee that a message or URL is safe.
- Message classification depends on the trained model and its training data.
- Scan statistics represent records saved by the application, not overall scam activity.
- Avoid entering sensitive personal information into the application.

## Future Improvements

Potential improvements include:

- Integration with reputable URL reputation and threat-intelligence services.
- Expanded and more diverse training datasets.
- Additional evaluation using precision, recall, F1-score, and confusion matrices.
- Improved URL analysis and explainability of detected warning indicators.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.