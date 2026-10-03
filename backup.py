from flask import Flask, render_template, request

from phishing_detector import analyze_email


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    sender = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    email_body = request.form.get("email_body", "").strip()

    result = analyze_email(
        sender,
        subject,
        email_body
    )

    return render_template(
        "result.html",
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)