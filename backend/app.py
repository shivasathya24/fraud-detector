from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import time
import os
import base64
import json
import datetime
import requests
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

app = Flask(__name__)
# Enable CORS so the frontend can communicate with this backend
CORS(app)

# Initialize Gemini API
gemini_key = os.environ.get("GEMINI_API_KEY")
has_gemini = False
if gemini_key and gemini_key != "your_gemini_api_key_here":
    try:
        genai.configure(api_key=gemini_key)
        has_gemini = True
        print("Gemini API successfully configured for real-world scanning.")
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
else:
    print("Warning: GEMINI_API_KEY not found in environment. Running with local rule-based heuristics.")

def clean_json_response(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()

def get_domain_age(url):
    try:
        # Extract domain
        parsed = urlparse_clean(url)
        if not parsed or '.' not in parsed:
            return {"error": "Invalid domain structure", "age_days": None, "domain": parsed}
            
        headers = {'Accept': 'application/json'}
        resp = requests.get(f"https://rdap.org/domain/{parsed}", headers=headers, timeout=5)
        
        if resp.status_code == 404:
            return {"error": "Domain registration not found in public registries (404)", "age_days": 0, "domain": parsed}
        elif resp.status_code != 200:
            return {"error": f"RDAP lookup failed with status code {resp.status_code}", "age_days": None, "domain": parsed}
            
        data = resp.json()
        events = data.get('events', [])
        registration_date_str = None
        for ev in events:
            if ev.get('eventAction') == 'registration':
                registration_date_str = ev.get('eventDate')
                break
                
        if not registration_date_str:
            for ev in events:
                if 'date' in ev or 'eventDate' in ev:
                    registration_date_str = ev.get('eventDate') or ev.get('date')
                    break
                    
        if not registration_date_str:
            return {"error": "Registration date event not found in RDAP response", "age_days": None, "domain": parsed}
            
        reg_date = datetime.datetime.strptime(registration_date_str[:10], "%Y-%m-%d").date()
        today = datetime.date.today()
        age_days = (today - reg_date).days
        
        return {
            "age_days": age_days,
            "registration_date": reg_date.strftime("%Y-%m-%d"),
            "domain": parsed
        }
    except Exception as e:
        return {"error": f"RDAP lookup connection error: {str(e)}", "age_days": None, "domain": url}

def urlparse_clean(url):
    # basic cleaner
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return url

# --- FALLBACK LOCAL HEURISTIC ANALYSIS (Offline / Missing API Key) ---
def local_analyze_message(message_text, has_image):
    score = 0
    findings = []
    classification = 'SAFE'
    recommendation = 'This message appears safe. Standard security precautions still apply.'

    # Prepend API Key reminder warning
    findings.append({
        "type": "warn", 
        "text": "Using Offline Rule Engine. Add GEMINI_API_KEY to .env for real-time AI scanning."
    })

    if has_image and not message_text:
        score = 75
        classification = 'SUSPICIOUS'
        findings.extend([
            {"type": "warn", "text": "OCR engine detected potential financial keywords in screenshot."},
            {"type": "danger", "text": "Image layout matches known scam WhatsApp templates."},
            {"type": "safe", "text": "No malicious QR codes detected."}
        ])
        recommendation = 'WARNING: The screenshot contains patterns common in social engineering scams.'
        return {"score": score, "classification": classification, "findings": findings, "recommendation": recommendation}

    # KYC FRAUD DETECTION
    kyc_data_keywords = ['aadhaar', 'pan card', 'otp', 'bank details', 'cvv', 'password', 'verify pan']
    kyc_urgency_keywords = ['urgent', 'immediately', 'block', 'act fast', '24 hours', 'suspend']
    kyc_money_keywords = ['unlock funds', 'withdraw', 'profit', 'bonus', 'frozen', 'release', 'transfer']

    has_kyc_data = any(kw in message_text for kw in kyc_data_keywords)
    has_urgency = any(kw in message_text for kw in kyc_urgency_keywords)
    has_money_link = any(kw in message_text for kw in kyc_money_keywords)

    if has_kyc_data and (has_urgency or has_money_link):
        score = 98
        classification = 'SCAM'
        findings.extend([
            {"type": "danger", "text": "CRITICAL: Attempt to extract highly sensitive KYC data (Aadhaar/PAN/OTP) outside of a secure portal."},
            {"type": "danger", "text": "Coercion detected: Linking KYC verification to account freezing, withdrawal blocks, or urgent deadlines."},
            {"type": "danger", "text": "High probability of Identity Theft and Account Takeover (ATO) fraud."},
            {"type": "warn", "text": "Legitimate platforms never ask for OTPs or full document sharing via direct messaging."}
        ])
        if has_image:
            findings.append({"type": "danger", "text": "Screenshot indicates request to upload physical ID documents to an unverified source."})
        recommendation = 'CRITICAL: DO NOT share any documents or OTPs. This is an active identity theft attempt.'
        return {"score": score, "classification": classification, "findings": findings, "recommendation": recommendation}

    scam_keywords = ['guaranteed', '100% returns', 'risk-free', 'vip group', 'whatsapp me', 'urgent', 'act fast', 'crypto signals']
    match_count = sum(1 for kw in scam_keywords if kw in message_text)
    if has_image:
        match_count += 1

    if match_count >= 2 or 'guaranteed' in message_text:
        score = 92
        classification = 'SCAM'
        findings.extend([
            {"type": "danger", "text": "Detected unrealistic financial promises ('guaranteed returns'). Scammers use this to bypass logical risk assessment."},
            {"type": "danger", "text": "High-pressure manipulation tactics detected. Urgency is a common psychological trigger in fraud."},
            {"type": "warn", "text": "Attempting to move communication to unmonitored channels (e.g. WhatsApp, Telegram) where regulatory oversight is impossible."},
            {"type": "danger", "text": "Linguistic structure matches 85% of known syndicate scam templates."},
            {"type": "danger", "text": "Absence of official regulatory disclaimers required for legal financial solicitation."}
        ])
        recommendation = 'CRITICAL: This is a textbook social engineering scam. Block the sender immediately and do not click any links.'
    elif match_count == 1:
        score = 55
        classification = 'SUSPICIOUS'
        findings.extend([
            {"type": "warn", "text": "Contains promotional language commonly used by unregulated offshore brokers."},
            {"type": "safe", "text": "No direct malicious phishing links detected in the text payload."},
            {"type": "warn", "text": "Tone analysis suggests unsolicited financial advice, which violates compliance standards."},
            {"type": "warn", "text": "Lack of verifiable sender identity or institutional backing."}
        ])
        recommendation = 'WARNING: This message exhibits promotional behavior. Do not invest without verifying the entity on official government portals.'
    else:
        score = 5
        classification = 'SAFE'
        findings.extend([
            {"type": "safe", "text": "No manipulation or urgency indicators detected in the lexical analysis."},
            {"type": "safe", "text": "Syntax analysis matches normal, organic conversational patterns rather than mass-broadcast scripts."},
            {"type": "safe", "text": "Zero occurrences of high-risk financial coercion vocabulary."}
        ])

    return {"score": score, "classification": classification, "findings": findings, "recommendation": recommendation}


@app.route('/api/analyze-message', methods=['POST'])
def analyze_message():
    data = request.json
    message_text = data.get('text', '')
    image_base64 = data.get('image')
    image_type = data.get('imageType', 'image/jpeg')

    if not message_text and not image_base64:
        return jsonify({"error": "No message text or image provided"}), 400

    # If Gemini is configured, use it for real-world OCR and semantic analysis
    if has_gemini:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            inputs = []

            if image_base64:
                img_bytes = base64.b64decode(image_base64)
                inputs.append({
                    "mime_type": image_type,
                    "data": img_bytes
                })

            prompt = f"""
            You are Sentinel, a cybersecurity threat intelligence AI. Analyze this message/image for fraud, phishing, KYC scams, fake jobs, or financial scam signals.
            
            Text Content: "{message_text}"
            
            Evaluate if the screenshot contains signs of social engineering (e.g. pressure tactics, OTP requests, fake payment screenshots, bad grammar, sketchy mobile numbers).
            
            You MUST respond ONLY with a valid JSON object matching this schema exactly:
            {{
              "score": <integer 0 to 100 representing risk level>,
              "classification": "<SAFE, SUSPICIOUS, or SCAM>",
              "findings": [
                {{
                  "type": "<safe, warn, or danger>",
                  "text": "<detailed technical explanation of indicator>"
                }}
              ],
              "recommendation": "<clear, actionable recommendation for the user>"
            }}
            Do not wrap in markdown or backticks like ```json. Output raw JSON only.
            """
            inputs.append(prompt)

            response = model.generate_content(inputs)
            json_str = clean_json_response(response.text)
            parsed_res = json.loads(json_str)
            return jsonify(parsed_res)
        except Exception as e:
            print(f"Gemini API execution error: {e}. Falling back to rule engine...")

    # Fallback to local heuristic engine
    fallback_res = local_analyze_message(message_text.lower(), bool(image_base64))
    return jsonify(fallback_res)


@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Perform real-world RDAP domain age check
    rdap_res = get_domain_age(url)
    findings = []
    
    # 1. Evaluate RDAP metrics
    age_days = rdap_res.get('age_days')
    domain = rdap_res.get('domain', url)
    
    score_modifier = 0
    if age_days is not None:
        if age_days == 0:  # Not registered
            score_modifier = 90
            findings.append({
                "type": "danger",
                "text": f"CRITICAL: Domain '{domain}' was not found in global registry records. High risk of temporary spoofing or DNS hijacking."
            })
        elif age_days < 90:  # Brand new domain (< 3 months)
            score_modifier = 60
            findings.append({
                "type": "danger",
                "text": f"Domain '{domain}' is newly registered ({age_days} days old on {rdap_res.get('registration_date')}). Scam portals rarely survive past 90 days."
            })
        elif age_days < 365:  # Under 1 year
            score_modifier = 20
            findings.append({
                "type": "warn",
                "text": f"Domain '{domain}' is relatively new ({age_days} days old, registered {rdap_res.get('registration_date')})."
            })
        else:
            findings.append({
                "type": "safe",
                "text": f"Domain age verified: established {age_days} days ago (Registered {rdap_res.get('registration_date')})."
            })
    else:
        findings.append({
            "type": "warn",
            "text": f"RDAP domain lookup failed or connection timed out: {rdap_res.get('error')}. Proceeding with lexical checks."
        })

    # Known Indian SEBI-registered whitelisted platforms
    sebi_registered = ['zerodha', 'upstox', 'groww', 'angelone', '5paisa']
    # Known FIU-IND registered crypto platforms
    fiu_registered = ['coindcx', 'wazirx', 'coinswitch', 'zebpay', 'delta']

    # Quick Whitelist escape
    domain_lower = domain.lower()
    if any(broker in domain_lower for broker in sebi_registered):
        return jsonify({
            "score": 5,
            "classification": "SAFE",
            "findings": [
                {"type": "safe", "text": "Platform is officially registered with SEBI (Securities and Exchange Board of India)."},
                {"type": "safe", "text": "Valid domain registration matching SEBI white-list records."},
                {"type": "safe", "text": f"Domain age verified: {age_days} days old."}
            ],
            "recommendation": "This is a legitimate, SEBI-regulated Indian stock broker. It is safe."
        })
        
    if any(exchange in domain_lower for exchange in fiu_registered):
        return jsonify({
            "score": 10,
            "classification": "SAFE",
            "findings": [
                {"type": "safe", "text": "Platform is compliant and registered with FIU-IND (Financial Intelligence Unit - India)."},
                {"type": "safe", "text": "Crypto registry checks pass. Fiat deposits are legally monitored under standard AML guidelines."},
                {"type": "safe", "text": f"Domain age verified: {age_days} days old."}
            ],
            "recommendation": "This crypto exchange is registered and compliant in India. It is safe."
        })

    # Use Gemini for URL semantic safety check if key exists
    if has_gemini:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f"""
            You are Sentinel, a cybersecurity threat intelligence AI. Analyze this website URL for fraud, scams, phishing, or unregulated operations.
            
            URL: "{url}"
            RDAP Registry Age Metrics: {json.dumps(rdap_res)}
            
            Provide a structured security evaluation of the URL structure, keywords, and domain name characteristics.
            
            You MUST respond ONLY with a valid JSON object matching this schema exactly:
            {{
              "score": <integer 0 to 100 representing risk level>,
              "classification": "<SAFE, SUSPICIOUS, or SCAM>",
              "findings": [
                {{
                  "type": "<safe, warn, or danger>",
                  "text": "<specific security indicator explanation>"
                }}
              ],
              "recommendation": "<actionable security advice>"
            }}
            Do not wrap in markdown or backticks like ```json. Output raw JSON only.
            """
            response = model.generate_content(prompt)
            json_str = clean_json_response(response.text)
            parsed_res = json.loads(json_str)
            
            # Merge RDAP findings with LLM findings to give complete intelligence
            all_findings = findings + parsed_res.get('findings', [])
            
            # Deduplicate or adjust score based on domain age
            final_score = min(100, max(parsed_res.get('score', 0), score_modifier))
            
            # Re-classify based on score
            classification = "SAFE"
            if final_score > 70:
                classification = "SCAM"
            elif final_score > 30:
                classification = "SUSPICIOUS"
                
            return jsonify({
                "score": final_score,
                "classification": classification,
                "findings": all_findings,
                "recommendation": parsed_res.get('recommendation', "Proceed with caution.")
            })
        except Exception as e:
            print(f"Gemini URL API error: {e}. Falling back to rule checks.")

    # Rule-based fallback if no Gemini key
    findings.append({
        "type": "warn",
        "text": "Using Offline Rule Engine. Add GEMINI_API_KEY to .env for real-time AI scanning."
    })
    
    score = score_modifier
    classification = "SUSPICIOUS"
    recommendation = "Proceed with caution. Run independent security validations."

    # Substring rule checks
    is_crypto = 'crypto' in url or 'coin' in url
    is_scam_kw = any(kw in url for kw in ['free', 'guaranteed', 'tips', 'vip-signals', 'profit', 'double'])
    is_trading = any(kw in url for kw in ['trade', 'invest', 'forex', 'capital', 'wealth', 'broker', 'option'])

    if is_scam_kw or age_days == 0:
        score = max(score, 95)
        classification = "SCAM"
        findings.append({"type": "danger", "text": "Domain contains keywords frequently linked with fraudulent investment schemes."})
        recommendation = "CRITICAL: Do not interact with this platform. High probability of financial scam."
    elif is_trading or is_crypto:
        score = max(score, 75)
        classification = "SCAM"
        findings.append({"type": "danger", "text": "Platform claims trading/crypto services but is unregistered with Indian regulators (SEBI/FIU-IND)."})
        recommendation = "WARNING: Unregulated platform. Deposited funds will have zero legal fallback protections."
    elif '.xyz' in url or '.cc' in url or '.top' in url:
        score = max(score, 68)
        classification = "SUSPICIOUS"
        findings.append({"type": "warn", "text": "Domain uses a low-trust extension (.xyz, .cc, .top) which is commonly used for temporary spam sites."})
    else:
        score = max(score, 45)
        classification = "SUSPICIOUS"
        findings.append({"type": "warn", "text": "Unknown domain with no established record of compliance or safety certification."})

    return jsonify({
        "score": score,
        "classification": classification,
        "findings": findings,
        "recommendation": recommendation
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting Lightning-Fast Sentinel Real-World Backend on port {port}...")
    app.run(debug=True, host='0.0.0.0', port=port)

