
from app import analyze_message


def test_prediction_consistency():
    message = (
        "URGENT: Your bank account will be blocked. "
        "Click this link to verify your account immediately."
    )

    results = [analyze_message(message) for _ in range(5)]

    scores = [result["score"] for result in results]
    statuses = [result["status"] for result in results]

    assert len(set(scores)) == 1, f"Inconsistent scores: {scores}"
    assert len(set(statuses)) == 1, f"Inconsistent statuses: {statuses}"

    print("PASS: All 5 predictions have identical scores and statuses.")
    print(f"Score: {scores[0]}%")
    print(f"Status: {statuses[0]}")


if __name__ == "__main__":
    test_prediction_consistency()
