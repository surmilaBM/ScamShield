
from flask import Flask, render_template, request
import joblib
import re

app = Flask(__name__)

model = joblib.load("scam_model.joblib")


def get_warnings(message):
    text = message.lower()
    warnings = []

    checks = {
        "Urgent or threatening language": [
            r"\b(urgent|immediately|blocked|suspended|disconnect|expire)\b"
        ],
        "Requests for sensitive information": [
            r"\b(otp|pin|password|cvv|aadhaar|aadhar)\b"
        ],
        "Possible payment or reward scam": [
            r"\b(prize|winner|won|reward|processing fee|claim your)\b"
        ],
        "Possible suspicious link": [
            r"https?://\S+|\bwww\.\S+"
        ],
        "UPI or banking-related wording": [
            r"\b(upi|kyc|bank account|bank details|refund)\b"
        ],
        "Possible job or investment offer": [
            r"\b(work from home|guaranteed returns|registration fee|investment)\b"
        ],
    }

    for warning, patterns in checks.items():
        if any(re.search(pattern, text) for pattern in patterns):
            warnings.append(warning)

    return warnings


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            prediction = model.predict([message])[0]
            probabilities = model.predict_proba([message])[0]
            classes = list(model.classes_)
            spam_score = float(probabilities[classes.index("spam")]) * 100

            warnings = get_warnings(message)

            if prediction == "spam":
                status = "Suspicious"
                explanation = (
                    "The model found patterns associated with spam messages. "
                    "Check the warning signs below before taking action."
                )
            else:
                status = "Likely legitimate"
                explanation = (
                    "The model classified this message as ham. "
                    "This does not guarantee that the message is safe."
                )

            result = {
                "status": status,
                "score": round(spam_score),
                "warnings": warnings,
                "explanation": explanation,
            }

        else:
            result = {
                "status": "No message entered",
                "score": 0,
                "warnings": [],
                "explanation": "Paste a message before running the analysis.",
            }

    return render_template("index.html", result=result, message=message)


if __name__ == "__main__":
    app.run(debug=True)
