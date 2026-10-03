
import streamlit as st
import joblib

from threat_intelligence import analyze_threats


# ---------- Load Model ----------
model = joblib.load("phishing_model.pkl")


# ---------- Page Configuration ----------
st.set_page_config(
    page_title="Phishing Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ---------- Session State ----------
if "emails_analyzed" not in st.session_state:
    st.session_state.emails_analyzed = 0

if "phishing_detected" not in st.session_state:
    st.session_state.phishing_detected = 0

if "safe_emails" not in st.session_state:
    st.session_state.safe_emails = 0


# ---------- Custom CSS ----------
st.markdown("""
<style>
    .main {
        background-color: #f5f7fb;
    }

    .dashboard-title {
        font-size: 36px;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 5px;
    }

    .subtitle {
        color: #6b7280;
        font-size: 16px;
        margin-bottom: 25px;
    }

    .card {
        background-color: white;
        padding: 22px;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }

    .card-title {
        font-size: 15px;
        color: #6b7280;
        margin-bottom: 8px;
    }

    .card-value {
        font-size: 28px;
        font-weight: 700;
        color: #111827;
    }

    .section-title {
        font-size: 23px;
        font-weight: 650;
        color: #1f2937;
        margin-top: 25px;
    }
</style>
""", unsafe_allow_html=True)


# ---------- Header ----------
st.markdown(
    '<div class="dashboard-title">🛡️ Phishing Email Detection Dashboard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Analyze suspicious emails, detect phishing indicators and assess risk.</div>',
    unsafe_allow_html=True
)


# ---------- Sidebar ----------
with st.sidebar:

    st.header("⚙️ Dashboard")

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Email Analysis",
            "Awareness"
        ]
    )

    st.divider()

    st.info(
        "Use Email Analysis to check an email for possible phishing indicators."
    )



if page == "Dashboard":

    st.markdown(
        '<div class="section-title">📊 Security Overview</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Emails Analyzed</div>
            <div class="card-value">{st.session_state.emails_analyzed}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Phishing Detected</div>
            <div class="card-value">{st.session_state.phishing_detected}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="card">
            <div class="card-title">Safe Emails</div>
            <div class="card-value">{st.session_state.safe_emails}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown("""
        <div class="card">
            <div class="card-title">System Status</div>
            <div class="card-value">Active</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown(
        '<div class="section-title">🔍 Quick Analysis</div>',
        unsafe_allow_html=True
    )

    st.write(
        "Go to **Email Analysis** from the sidebar to analyze a suspicious email."
    )



elif page == "Email Analysis":

    st.markdown(
        '<div class="section-title">📧 Email Analysis</div>',
        unsafe_allow_html=True
    )

    subject = st.text_input(
        "Email Subject",
        placeholder="Enter email subject"
    )

    sender = st.text_input(
        "Sender Email",
        placeholder="example@gmail.com"
    )

    body = st.text_area(
        "Email Content",
        placeholder="Paste the email content here...",
        height=250
    )

    if st.button("🔎 Analyze Email", use_container_width=True):

        # Check whether email content was entered
        if not body or not body.strip():

            st.warning("Please enter the email before analyzing.")

        else:

            st.success("Email received successfully.")

            st.subheader("Analysis Result")

            st.write("**Subject:**", subject)
            st.write("**Sender:**", sender)

            # ---------- Machine Learning Prediction ----------
            prediction = model.predict([body])[0]

            st.write("**Prediction:**", prediction)

            # ---------- Update Dashboard Counters ----------
            st.session_state.emails_analyzed += 1

            if prediction == "phishing":

                st.session_state.phishing_detected += 1

                st.error("🚨 PHISHING EMAIL DETECTED")

            else:

                st.session_state.safe_emails += 1

                st.success("✅ EMAIL APPEARS LEGITIMATE")


            # ---------- Threat Intelligence ----------
            threat_result = analyze_threats(
                subject,
                sender,
                body
            )

            st.subheader("🛡️ Threat Intelligence")

            st.write(
                "**Risk Level:**",
                threat_result["risk"]
            )

            if threat_result["indicators"]:

                st.write("**Threat Indicators:**")

                for indicator in threat_result["indicators"]:

                    st.warning("⚠️ " + indicator)

            else:

                st.success(
                    "✅ No obvious threat indicators detected"
                )



elif page == "Awareness":

    st.markdown(
        '<div class="section-title">🧠 Phishing Awareness</div>',
        unsafe_allow_html=True
    )

    st.write("### Common Phishing Warning Signs")

    st.markdown("""
    - 🚨 Urgent or threatening messages
    - 🔗 Suspicious URLs
    - 📧 Unknown or unusual senders
    - 🔐 Requests for passwords or sensitive information
    - 💰 Unexpected payment requests
    - 📎 Suspicious attachments
    """)

    st.info(
        "Always verify the sender and URL before clicking links in suspicious emails."
    )


    st.write("### How to Stay Safe from Phishing")

    st.markdown("""
    - 🔍 **Check the sender:** Make sure the email address belongs to the expected organization.
    - 🔗 **Check links carefully:** Hover over links before clicking and look for unusual domains.
    - 🔐 **Never share passwords:** Legitimate organizations generally do not ask for your password by email.
    - 💳 **Verify payment requests:** Confirm unexpected financial requests through a separate trusted channel.
    - 📎 **Be careful with attachments:** Do not open unexpected files from unknown senders.
    - ⏱️ **Do not rush:** Urgent messages are a common phishing tactic. Take time to verify them.
    """)


    st.write("### What to Do If You Suspect Phishing")

    st.warning(
        "Do not click links, open attachments, or provide sensitive information. "
        "Report the email to your organization or email provider and delete it."
    )


    st.write("### Quick Phishing Checklist")

    st.checkbox("I checked the sender's email address")

    st.checkbox("I checked the destination of suspicious links")

    st.checkbox("I did not provide passwords or sensitive information")

    st.checkbox("I verified unexpected requests independently")

