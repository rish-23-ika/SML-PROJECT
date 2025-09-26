import os
import json
import re
import subprocess
from datetime import datetime
from dateutil import parser as dtparser

import requests
import streamlit as st
from fpdf import FPDF

# --------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & STYLING
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="Fake Account Detector (X/Twitter)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
/* --- General & Theme --- */
.main { background: #0E1117; } /* Streamlit's default dark background */
h1,h2,h3 { color: #FAFAFA; }
section[data-testid="stSidebar"] { background: #0a2a43; }
section[data-testid="stSidebar"] * { color: #f2f6fa !important; }

/* --- Custom Cards & Badges --- */
.metric-card {
  background-color: #1F222B;
  border-radius: 16px;
  padding: 14px 16px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  margin-bottom: 10px;
}
.score-badge {
  font-size: 36px; font-weight: 800; padding: 6px 16px; border-radius: 12px; display:inline-block;
}
.info-box {
  background-color: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  padding: 12px 16px;
  border-radius: 12px;
  margin-bottom: 10px;
  font-size: 15px;
}

/* --- Flags for Analysis Breakdown --- */
.flag-good   { background:#1E2F28; border-left:6px solid #28A745; padding:10px; border-radius:8px; margin-bottom: 8px; }
.flag-warn   { background:#332B1B; border-left:6px solid #FFC107; padding:10px; border-radius:8px; margin-bottom: 8px; }
.flag-bad    { background:#331E22; border-left:6px solid #DC3545; padding:10px; border-radius:8px; margin-bottom: 8px; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Fake Account Detector for X (Twitter)")
st.caption("Type a Twitter/X handle to analyze likely impersonation/bot risk using behavioral, network, and content signals.")

with st.sidebar:
    st.header("🛡️ Privacy & Security")
    with st.expander("Show our Privacy-First Commitment"):
        st.markdown("""
        This tool is built with a "Privacy by Design" philosophy. Here's our commitment to you and the X community:
        - **✅ Read-Only Access:** The application only reads public-facing data. It does not post, follow, or perform any write actions on any account.
        - **✅ No Data Storage:** We do **not** store, save, or log any Twitter data. All analysis is done ephemerally in memory for each request and is discarded immediately after you close the session.
        - **✅ Public Data Only:** This tool only analyzes data that is already publicly visible on the X platform. It does not access protected tweets or private information.
        - **✅ Secure API Key Handling:** Our connection to the X API is made using secure, industry-standard practices. API keys are never exposed on the client-side.
        - **✅ Ethical Use:** This tool is intended for educational and personal safety purposes to identify potential bot or spam networks. It is not intended for harassment, surveillance, or any malicious activity.
        """)

# --------------------------------------------------------------------------
# 2. DATA FETCHING HELPERS
# --------------------------------------------------------------------------
@st.cache_data(ttl="10m")
def get_user_and_tweets(username: str):
    def try_x_api_user(username_str: str):
        token = os.getenv("X_BEARER")
        if not token: return None, None
        try:
            base = "https://api.twitter.com/2"
            uf = "created_at,description,id,location,name,profile_image_url,protected,public_metrics,url,username,verified"
            url_user = f"{base}/users/by/username/{username_str}?user.fields={uf}"
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(url_user, headers=headers, timeout=20)
            if r.status_code != 200: return None, None
            user_data = r.json().get("data")
            tweets = []
            if user_data:
                uid = user_data["id"]
                tf = "created_at,public_metrics,source"
                r2 = requests.get(f"{base}/users/{uid}/tweets?max_results=100&tweet.fields={tf}", headers=headers, timeout=20)
                if r2.status_code == 200: tweets = r2.json().get("data", [])
            return user_data, tweets
        except Exception: return None, None

    def try_snscrape_user(username_str: str):
        try:
            cmd_user = ["snscrape", "--jsonl", "--max-results", "1", f"twitter-user {username_str}"]
            p = subprocess.run(cmd_user, capture_output=True, text=True, timeout=30)
            if p.returncode != 0 or not p.stdout.strip(): return None, None
            user_line = json.loads(p.stdout.strip().splitlines()[0])
            cmd_tweets = ["snscrape", "--jsonl", "--max-results", "100", f"twitter-user {username_str}"]
            p2 = subprocess.run(cmd_tweets, capture_output=True, text=True, timeout=45)
            tweets_data = []
            if p2.returncode == 0 and p2.stdout.strip():
                for line in p2.stdout.splitlines():
                    try: tweets_data.append(json.loads(line))
                    except: pass
            user_data = {"id": str(user_line.get("id")),"username": user_line.get("username"),"name": user_line.get("displayname"),"created_at": user_line.get("created"),"description": user_line.get("description"),"location": user_line.get("location"),"profile_image_url": user_line.get("profileImageUrl"),"verified": bool(user_line.get("verified")),"public_metrics": {"followers_count": int(user_line.get("followersCount") or 0),"following_count": int(user_line.get("friendsCount") or 0),"tweet_count": int(user_line.get("statusesCount") or 0),}}
            norm_tweets = [{"id": str(t.get("id")),"text": t.get("rawContent") or "","created_at": t.get("date"), "source": t.get("sourceLabel") or ""} for t in tweets_data]
            return user_data, norm_tweets
        except Exception: return None, None

    user, tweets = try_x_api_user(username)
    source = "AAAAAAAAAAAAAAAAAAAAAKns3wEAAAAAz5GPv7wRECqGOGcR4rfooc%2BTm1M%3DV1IiUiNtJJnyKhfC2P5qzJawtr1c93UMRnnxcoiszhwz8HmrbF"
    if not user:
        st.warning("Could not use X API, falling back to snscrape. This may be slower.", icon="⚠️")
        user, tweets = try_snscrape_user(username)
        source = "snscrape"
    return user, tweets, source

# --------------------------------------------------------------------------
# 3. SCORING AND PDF GENERATION FUNCTIONS
# --------------------------------------------------------------------------
def compute_fake_score(user, tweets):
    reasons = {'good': [], 'bad': []}
    score = 0
    followers = user["public_metrics"]["followers_count"]
    following = user["public_metrics"]["following_count"]
    if followers < 50 and following > 300:
        score += 30
        reasons['bad'].append(f"Suspicious Follower Ratio ({followers} followers / {following} following): +30")
    else:
        reasons['good'].append("Account has a healthy follower/following ratio.")
    if len(user.get("description") or "") > 10:
        reasons['good'].append("Profile has a descriptive bio.")
    else:
        score += 20
        reasons['bad'].append("Profile has no significant bio: +20")
    if user.get("profile_image_url") and 'default_profile' not in user.get("profile_image_url"):
        reasons['good'].append("Account has a custom profile picture.")
    else:
        score += 20
        reasons['bad'].append("Account is using a default profile picture: +20")
    if user.get("verified"):
        score -= 25
        reasons['good'].append("Account is verified by X: -25")
    created_date = dtparser.parse(user["created_at"])
    now_aware = datetime.now(created_date.tzinfo)
    account_age_days = (now_aware - created_date).days
    if account_age_days < 30:
        score += 25
        reasons['bad'].append(f"Account is very new ({account_age_days} days old): +25")
    elif account_age_days < 180:
        score += 15
        reasons['bad'].append(f"Account is relatively new ({account_age_days} days old): +15")
    else:
        reasons['good'].append("Account is well-established and has existed for a long time.")
    if tweets:
        if len(tweets) < 10:
            score += 20
            reasons['bad'].append(f"Account has very few recent tweets ({len(tweets)} found): +20")
        total_tweets = len(tweets)
        link_tweets = sum(1 for t in tweets if re.search(r"http[s]?://|www\.", t.get("text", "")))
        link_ratio = (link_tweets / total_tweets) * 100 if total_tweets > 0 else 0
        if link_ratio > 50:
            score += 20
            reasons['bad'].append(f"Very high link percentage in recent tweets ({link_ratio:.0f}%): +20")
        elif link_ratio > 20:
            score += 10
            reasons['bad'].append(f"High link percentage in recent tweets ({link_ratio:.0f}%): +10")
        else:
            reasons['good'].append("Low percentage of tweets containing links.")
    return max(0, min(100, score)), account_age_days, reasons

def generate_pdf_report(username, score, account_created, followers, following, tweets, reasons_list):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 18)
    pdf.cell(0, 12, f'Fake Account Analysis: @{username}', 0, 1, 'C')
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, 'Summary', 0, 1)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 8, f"Final Fakeness Score: {score}/100", 0, 1)
    pdf.cell(0, 8, f"Account Created: {account_created}", 0, 1)
    pdf.cell(0, 8, f"Followers: {followers:,}", 0, 1)
    pdf.cell(0, 8, f"Following: {following:,}", 0, 1)
    pdf.cell(0, 8, f"Total Tweets: {tweets:,}", 0, 1)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, 'Analysis Breakdown:', 0, 1)
    pdf.set_font("Arial", '', 11)
    if reasons_list['bad']:
        for reason in reasons_list['bad']:
            pdf.multi_cell(0, 7, f"- {reason.replace('**', '')}")
    else:
        pdf.multi_cell(0, 7, "- No significant behavioral anomalies detected.")
    pdf.ln(5)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 10, f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
    return pdf.output(dest='S').encode('latin-1')

# --------------------------------------------------------------------------
# 4. MAIN APP INTERFACE
# --------------------------------------------------------------------------
username = st.text_input("Enter Twitter/X handle (without @)", placeholder="jack")
go = st.button("Analyze")

if go and username.strip():
    if not re.match(r"^[A-Za-z0-9_]{1,15}$", username.strip()):
        st.error("❌ Invalid Twitter Handle. Please enter a valid handle (letters, numbers, underscores).", icon="🚨")
    else:
        with st.spinner(f"Analyzing @{username.strip()}... This may take a moment."):
            user, tweets, source = get_user_and_tweets(username.strip())

        if not user:
            st.error("❌ Could not fetch this handle. It may not exist, or there could be an issue with the data source.", icon="🚨")
        else:
            score, account_age_days, reasons = compute_fake_score(user, tweets)
            
            st.subheader(f"@{user['username']} — {user.get('name','')}")
            st.caption(f"Source: {source}")
            st.write(user.get("description") or "_No bio provided_")
            
            st.markdown("---")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                color = "#28A745" if score < 30 else "#FFC107" if score < 60 else "#DC3545"
                st.markdown(
                    f'<div class="metric-card"><span class="score-badge" style="color:{color}">Fakeness Score: {score}/100</span></div>',
                    unsafe_allow_html=True
                )
            with col2:
                 created_date_display = dtparser.parse(user["created_at"]).strftime("%B %d, %Y")
                 st.markdown(
                    f'<div class="info-box">🗓️ &nbsp; <strong>Account Created:</strong><br>{created_date_display} ({account_age_days} days ago)</div>',
                    unsafe_allow_html=True
                )

            st.write("") # Spacer

            c1, c2, c3 = st.columns(3)
            c1.metric("Followers", f"{user['public_metrics']['followers_count']:,}")
            c2.metric("Following", f"{user['public_metrics']['following_count']:,}")
            c3.metric("Tweets", f"{user['public_metrics']['tweet_count']:,}")

            st.markdown("---")
            
            st.subheader("🔎 Analysis Breakdown")
            if reasons['bad']:
                for reason in reasons['bad']:
                    st.markdown(f'<div class="flag-bad">❌ {reason}</div>', unsafe_allow_html=True)
            else:
                st.markdown(
                    f'<div class="flag-good">✅ No significant behavioral anomalies detected. This account appears to be legitimate based on the checks performed.</div>',
                    unsafe_allow_html=True
                )
            
            st.markdown("---")
            
            st.subheader("📄 Download Report")
            pdf_data = generate_pdf_report(
                username=user['username'], score=score, account_created=f"{created_date_display} ({account_age_days} days ago)",
                followers=user["public_metrics"]["followers_count"], following=user["public_metrics"]["following_count"],
                tweets=user["public_metrics"]["tweet_count"], reasons_list=reasons
            )
            st.download_button(
                label="Download Full Report as PDF", data=pdf_data,
                file_name=f"{user['username']}_report.pdf", mime="application/pdf"
            )
            
            # ----------------------------------------------------------------------
            # 5. REPORT SUSPICIOUS ACCOUNT BUTTONS (ALWAYS VISIBLE)
            # ----------------------------------------------------------------------
            st.markdown("---")
            st.subheader("⚠️ Report Account")
            st.write("If you believe this account is violating platform rules or local laws, you can report it directly:")

            col1, col2 = st.columns(2)

            twitter_report_url = f"https://x.com/i/flow/report-user?screen_name={username.strip()}"
            cybercell_report_url = "https://cybercrime.gov.in/"

            with col1:
                st.markdown(
                    f'<a href="{twitter_report_url}" target="_blank" style="text-decoration: none;">'
                    f'<button style="width:100%;background-color:#1DA1F2;color:white;padding:10px 20px;border:none;border-radius:8px;font-size:16px;cursor:pointer;">Report on X (Twitter)</button>'
                    f'</a>',
                    unsafe_allow_html=True
                )

            with col2:
                st.markdown(
                    f'<a href="{cybercell_report_url}" target="_blank" style="text-decoration: none;">'
                    f'<button style="width:100%;background-color:#DC3545;color:white;padding:10px 20px;border:none;border-radius:8px;font-size:16px;cursor:pointer;">Report to Cyber Cell India</button>'
                    f'</a>',
                    unsafe_allow_html=True
                )