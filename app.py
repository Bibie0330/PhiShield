from flask import Flask, render_template, request
import json

from detection.scoring import score_message

app = Flask(__name__)

# Load phishing keywords from JSON
with open("phishing_keywords.json", "r", encoding="utf-8") as f:
    phishing_keywords = json.load(f)

text = {
    "input_placeholder": "Enter your message here...",
    "analyze_btn": "Analyze",
    "tip": "Your texts will not be recorded or stored",
}

@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    processing = False

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        # Input validation (Security Element 7.5.1)
        if not message:
            return render_template(
                "index.html",
                message=message,
                text=text,
                error="Please enter a message to analyze."
            )

        processing = True

        # Generate phishing detection report
        report = score_message(message, phishing_keywords)

        return render_template(
            "result.html",
            text=text,
            report=report
        )

    return render_template(
        "index.html",
        message=message,
        text=text,
        processing=processing
    )


@app.route("/learn")
def learn():
    return render_template("learn.html", text=text)


if __name__ == "__main__":
    app.run(debug=True)