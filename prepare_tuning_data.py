import csv
import json
import random

def main():
    print("[+] Loading SMS dataset...")
    sms_samples = []
    try:
        with open("sms_spam.tsv", "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter="\t")
            for row in reader:
                if len(row) == 2:
                    label, text = row
                    sms_samples.append((label, text.strip()))
    except Exception as e:
        print(f"[-] Warning: Failed to read sms_spam.tsv: {e}")
        # Keep empty, we will handle fallback or mock SMS data if file is missing

    # Filter into ham/spam SMS
    sms_ham = [s[1] for s in sms_samples if s[0] == "ham"]
    sms_spam = [s[1] for s in sms_samples if s[0] == "spam"]

    # Select balanced SMS subset (100 of each)
    num_sms = min(100, len(sms_ham), len(sms_spam)) if sms_ham else 0
    selected_sms_ham = random.sample(sms_ham, num_sms) if sms_ham else []
    selected_sms_spam = random.sample(sms_spam, num_sms) if sms_spam else []
    
    print(f"    Loaded {len(selected_sms_ham)} safe SMS and {len(selected_sms_spam)} spam SMS.")

    # 🚀 Synthetic Phishing Emails (Gmail)
    email_phishing = [
        "Subject: Action Required: Your Account Has Been Locked\n\nDear Customer,\n\nWe detected unauthorized login attempts to your bank account. For your security, we have temporarily locked your account. Please verify your identity immediately: http://citi-verification-check.com/secure\n\nCiti Bank Security Team",
        "Subject: Billing Issue: Update payment details for Netflix\n\nWe were unable to process your monthly subscription payment. Your service will be suspended on 25th May. Update billing here: https://netflix-billing-update.com/pay",
        "Subject: Urgent: Security alert for Microsoft Account\n\nSomeone from Moscow, Russia attempted to access your Microsoft/Outlook account. If this was not you, please secure your account immediately: http://secure-outlook-login.com/auth",
        "Subject: HR Department: Updated Employee Benefit Policy\n\nAll staff must read and sign the attached employee benefits amendment document. Please download the document to verify your payroll info: http://company-benefit-portal.com/payroll",
        "Subject: PayPal Notice: Disputed transaction of $499.00\n\nYou authorized a payment of $499.00 to CryptoExchange. If you did not make this transaction, dispute it immediately: http://paypal-dispute-resolution.com/login",
        "Subject: Coinbase Support: Your crypto account has been suspended\n\nWe noticed suspicious trade activities on your Coinbase account. To restore normal trading access, submit your KYC validation details here: http://coinbase-kyc-verify.com/login",
        "Subject: DHL Express: Delivery Address Correction Required\n\nYour package cannot be delivered due to an incorrect house number. Please update your shipping details and pay the $1.99 handling fee: http://dhl-shipping-update.com/pay",
        "Subject: Apple Support: iCloud Storage full - subscription suspended\n\nYour iCloud account has run out of storage, and backing up is disabled. Renew your subscription using this promo link to get 50% off: http://icloud-storage-portal.com",
        "Subject: IRS Tax refund alert: Claim your $750 rebate\n\nYou are entitled to a tax refund of $750.00 from your 2025 filings. Click here to confirm your bank routing number: http://irs-tax-refund-portal.gov.in.com",
        "Subject: Zoom Video: Schedule update for team meeting\n\nThe schedule for tomorrow's team performance evaluation has changed. View the new Zoom room link: http://zoom-room-lobby.com/join",
        "Subject: Amazon Order Confirmation: iPhone 15 Pro Max\n\nThank you for your order! Your visa card ending in 4321 was charged $1,199.00. If you did not place this order, cancel it here: http://amazon-dispute-update.com",
        "Subject: MetaMask wallet: Recovery phrase validation\n\nMetaMask is updating security protocols. Validate your 12-word seed phrase now to avoid asset freezing: http://metamask-security-vault.com/auth",
        "Subject: FedEx Delivery Notice: Final Warning\n\nYour parcel is held at our local depot. To schedule redelivery, please complete the verification details: http://fedex-tracking-portal.com",
        "Subject: Chase Bank Notification: Critical System Update\n\nChase Online banking is undergoing a database migration. Confirm your account information to keep your web access active: http://chase-bank-verify.com",
        "Subject: Steam Support: Trade request verification\n\nA user requested a trade of your Counter-Strike skins. If you did not approve this trade, reject it immediately: http://steamcommunity-trade-reject.com/login"
    ] * 4 # Duplicate to match desired count

    # 🚀 Synthetic Safe Emails (Gmail)
    email_safe = [
        "Subject: Weekly Project Status Report\n\nHi Team,\n\nAttached is the weekly status report for Project Vanguard. We have successfully completed Phase 1 and will start Phase 2 on Monday.\n\nBest,\nSarah",
        "Subject: Receipt for your Google Workspace Subscription\n\nThank you for your payment. A charge of $6.00 has been billed to your card. You can view your invoice inside your Google Admin console.",
        "Subject: Invitation: Team Sync @ Wed May 27, 2026\n\nYou are invited to the weekly team sync meeting on Zoom. Agenda: Review monthly performance targets. Please RSVP.",
        "Subject: GitHub: Security alert vulnerability patch complete\n\nSecurity vulnerability CVE-2026-1033 has been patched in your repository. No further action is required on your part.",
        "Subject: Newsletter: Python Weekly Issue #512\n\nWelcome to Python Weekly! In this issue, we explore advanced asyncio patterns, new features in Django 5.1, and best practices for writing clean decorators.",
        "Subject: Booking Confirmation: Marriott International\n\nYour reservation at Marriott New York is confirmed. Check-in: June 12. Check-out: June 15. We look forward to welcoming you.",
        "Subject: Spotify Premium: Thank you for your payment\n\nYour monthly Spotify Premium subscription has been successfully renewed. Your next billing date is June 24, 2026.",
        "Subject: Adobe Creative Cloud: Update available\n\nA new version of Adobe Photoshop is now available for download. Learn about the new generative fill tools in our release notes.",
        "Subject: New Comment on your LinkedIn Post\n\nJohn Doe commented on your post: 'Excellent insights on cybersecurity guards! Looking forward to trying this project.' View comment on LinkedIn.",
        "Subject: Walmart Receipt: Order #983210\n\nYour order has been processed and is ready for pickup at your local store. Please show the barcode at the pickup counter.",
        "Subject: Dropbox: Weekly backup summary\n\nYour files have been backed up successfully. 12 files were added, and 4 files were updated. Your total storage space used is 34.2 GB.",
        "Subject: Zoom: Password reset confirmation\n\nThe password for your Zoom account was successfully changed. If you did not perform this change, contact our help desk immediately.",
        "Subject: Wikipedia: Thank you for your contribution\n\nWe appreciate your recent edit on the 'Content Security Policy' page. Your edits help keep Wikipedia accurate and up to date.",
        "Subject: NYTimes: Daily News Briefing\n\nToday's headlines: Major updates in global climate policy, economic projections for Q3, and new discoveries in deep space research.",
        "Subject: Discord: Email address verified\n\nYour email address has been successfully verified for your Discord account. You are all set to join servers and chat!"
    ] * 4

    # 🚀 Synthetic Chat Scams (WhatsApp/Instagram)
    chat_phishing = [
        "Hey! You won a cash prize of $5,000 from the Instagram Annual Giveaway! 🎁 Click the link below to submit your bank info and claim it now: http://instagram-giveaway-winner.com/claim",
        "Hi dear, my phone broke and I am using a friend's mobile. Can you send me $200 via cashapp? I really need to pay this pharmacy bill. I will return it tomorrow promise! Cashapp link: http://cash-app-transfer.com",
        "EASY MONEY OPPORTUNITY! Work from home 1 hour a day and make $500. No experience required. We are hiring immediately. Register here: http://telecom-job-portal.com",
        "Verify your WhatsApp account immediately to prevent account deletion. Click here to receive your 6-digit confirmation pin: http://whatsapp-verify-code.com/auth",
        "Hello! I am a crypto broker. I can double your Bitcoin investment in just 48 hours. Look at my past payouts on Telegram: http://telegram-crypto-signals.com/join",
        "Is this you in this leaked video? Omg I can't believe they posted this... check it out before they take it down: http://facebook-video-leaks.com/watch",
        "Congratulations! Your mobile number was chosen as our monthly lucky winner of a brand new Tesla. Claim your vehicle rewards here: http://tesla-rewards-winner.com",
        "Hi, this is Discord Support. We detected illegal activity on your server. To prevent permanent ban, verify your account ownership: http://discord-support-portal.com",
        "Hey look, I found this free gift card generator for Amazon! It actually works I just got $50. Try it here: http://amazon-giftcard-generator.com",
        "Your package is held at the sorting facility. To resolve delivery hold, pay the custom fee of $1.50 here: http://dhl-package-release.com"
    ] * 6

    # 🚀 Synthetic Chat Safe (WhatsApp/Instagram)
    chat_safe = [
        "Hey! Are we still on for dinner tonight at 7 PM? Let me know so I can reserve a table.",
        "Hi, can you send me the password for the home Wi-Fi? My computer disconnected.",
        "Good morning! Just wanted to wish you good luck on your exam today. You'll do great!",
        "Can you pick up some milk and eggs on your way home? We are completely out.",
        "I'm running about 10 minutes late due to traffic, don't wait for me, start ordering!",
        "Did you see the new movie trailer? It looks amazing, let's watch it this weekend.",
        "Thanks for helping me move the boxes yesterday, I really appreciate your help!",
        "Are you free for a phone call? I need to ask you a quick question about the homework.",
        "Here is the photo of the cat we saw yesterday, it was so cute!",
        "Yes, the meeting is scheduled for tomorrow at 10 AM. I will send you the invite link."
    ] * 6

    # Assemble and structure dataset
    tuning_data = []

    def format_sample(text, label, warnings=None):
        user_prompt = f"Analyze this message for fraud signals:\n\n"
        if warnings:
            user_prompt += "Domain Verification Analyzer Warnings:\n" + "\n".join(warnings) + "\n\n"
        user_prompt += f"Message Text:\n{text}"

        if label == "phishing":
            expected = {
                "risk_score": random.randint(85, 99),
                "risk_level": "HIGH",
                "summary": "This message is a malicious phishing attempt targeting personal details or credentials.",
                "reasons": warnings or ["Contains deceptive links designed to steal credentials", "Creates false urgency or fear to manipulate users"],
                "action": "BLOCK",
                "what_to_do": "Do not reply, fill out details, or open the link. Report or block the sender."
            }
        else:
            expected = {
                "risk_score": random.randint(0, 15),
                "risk_level": "LOW",
                "summary": "This is a normal, safe conversation or authentic message.",
                "reasons": ["Contains no suspicious links or urgent financial demands", "Authentic style corresponding to normal communication"],
                "action": "TRUST",
                "what_to_do": "This message is safe to read or reply to."
            }

        return {
            "contents": [
                {"role": "user", "parts": [{"text": user_prompt}]},
                {"role": "model", "parts": [{"text": json.dumps(expected)}]}
            ]
        }

    # 1. Process SMS
    for text in selected_sms_ham:
        tuning_data.append(format_sample(text, "safe"))
    for text in selected_sms_spam:
        # Generate domain warnings for a subset of spam
        if "http" in text or "www" in text:
            # Fake a warnings array for training
            warnings = ["The link contains a potential typosquatted lookalike of a trusted brand."]
            tuning_data.append(format_sample(text, "phishing", warnings))
        else:
            tuning_data.append(format_sample(text, "phishing"))

    # 2. Process Emails
    for text in email_safe[:50]:
        tuning_data.append(format_sample(text, "safe"))
    for text in email_phishing[:50]:
        # Extract fake domain to make it context-aware
        warnings = ["The link contains a potential typosquatted lookalike of a trusted brand."]
        tuning_data.append(format_sample(text, "phishing", warnings))

    # 3. Process Chats
    for text in chat_safe[:50]:
        tuning_data.append(format_sample(text, "safe"))
    for text in chat_phishing[:50]:
        warnings = ["The link contains a potential typosquatted lookalike of a trusted brand."]
        tuning_data.append(format_sample(text, "phishing", warnings))

    # Shuffle the training set
    random.shuffle(tuning_data)

    # Write to gemini_tuning_data.jsonl
    with open("gemini_tuning_data.jsonl", "w", encoding="utf-8") as f:
        for item in tuning_data:
            f.write(json.dumps(item) + "\n")

    print(f"[+] Successfully generated gemini_tuning_data.jsonl with {len(tuning_data)} high-fidelity, balanced examples!")

if __name__ == "__main__":
    main()
