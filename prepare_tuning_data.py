import os
import csv
import json
import random
import pandas as pd
from datasets import load_dataset

def clean_text(text, max_len=1000):
    if not isinstance(text, str):
        return ""
    # Strip whitespace and normalize spaces
    text = " ".join(text.split())
    # Truncate to avoid token limit errors during Gemini fine-tuning
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text.strip()

def format_sample(text, label, source_name, warnings=None):
    user_prompt = f"Analyze this message for fraud signals:\n\n"
    if warnings:
        user_prompt += "Domain Verification Analyzer Warnings:\n" + "\n".join(warnings) + "\n\n"
    user_prompt += f"Message Text:\n{text}"

    # Custom context-specific reasons based on the source dataset
    reasons = []
    if label == "phishing":
        score = random.randint(85, 99)
        risk_level = "HIGH"
        summary = "This message is a malicious phishing attempt targeting personal details or credentials."
        
        if "nigerian" in source_name.lower():
            reasons = [
                "Matches patterns associated with financial advance-fee fraud (419 scams).",
                "Offers unsolicited and unrealistic financial transfers or inheritance claims in exchange for upfront details."
            ]
        elif "whatsapp" in source_name.lower():
            reasons = [
                "Deceptive WhatsApp messaging trying to induce quick actions or credentials/pin sharing.",
                "Contains unsolicited offers or warning messages designed to compromise messaging accounts."
            ]
        elif "url" in source_name.lower() or "discord" in source_name.lower():
            reasons = [
                "Contains suspicious, unverified, or potentially malicious link domains.",
                "Promotes deceptive links aiming to harvest credentials or execute unauthorized downloads."
            ]
        elif "sms" in source_name.lower() or "smish" in source_name.lower():
            reasons = [
                "SMS/smishing spam pattern demanding immediate action or containing suspicious links.",
                "Uses urgent tone to request authentication details, bank verification, or package delivery fees."
            ]
        else:
            reasons = [
                "Contains deceptive links designed to steal credentials or private information.",
                "Uses false urgency, panic, or security threats to manipulate the user."
            ]
        
        action = "BLOCK"
        what_to_do = "Do not reply, fill out details, or open any links. Block the sender and report the content."
    else:
        score = random.randint(0, 15)
        risk_level = "LOW"
        summary = "This is a normal, safe conversation or authentic message."
        reasons = [
            "Contains no suspicious links or urgent financial demands.",
            "Authentic conversational or informational style corresponding to normal communication."
        ]
        action = "TRUST"
        what_to_do = "This message is safe to read or reply to."

    expected = {
        "risk_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "reasons": reasons,
        "action": action,
        "what_to_do": what_to_do
    }

    return {
        "contents": [
            {"role": "user", "parts": [{"text": user_prompt}]},
            {"role": "model", "parts": [{"text": json.dumps(expected)}]}
        ]
    }

def main():
    print("[+] Initializing ShieldIQ Multi-Source Data Preparation...")
    
    # Store tuples of (cleaned_text, label, source_name)
    all_samples = []
    
    # Target size per source to maintain a balanced dataset
    target_phishing = 150
    target_safe = 150

    # ----------------- HUGGING FACE DATASETS -----------------
    print("\n--- Processing Hugging Face Datasets ---")

    # 1. electricsheepafrica/Nigerian-banking-retail-transactions & electricsheepafrica/Nigerian-Financial-Transactions-and-Fraud-Detection-Dataset
    # (Skip or sample if they contain descriptions/fraud reasons)
    try:
        print("[+] Loading electricsheepafrica/Nigerian-banking-retail-transactions...")
        # If it contains text transaction description we use it, otherwise we safely fallback
        ds = load_dataset("electricsheepafrica/nigerian-banking-retail-transactions", split="train", timeout=10)
        # Check available columns to extract textual transactions
        cols = ds.column_names
        print(f"    Loaded. Columns: {cols}")
    except Exception as e:
        print(f"    [-] Skipping electricsheepafrica/nigerian-banking-retail-transactions: {e}")

    # 2. masakhane/afrisenti (Nigerian Pidgin English configuration)
    try:
        print("[+] Loading masakhane/afrisenti (Nigerian Pidgin Config)...")
        ds = load_dataset("masakhane/afrisenti", "pcm", split="train")
        safe_count = 0
        # Treat positive or neutral sentiment tweets as safe Nigerian context text
        for item in ds:
            if item["label"] in ["positive", "neutral"] and safe_count < target_safe:
                txt = clean_text(item["tweet"])
                if txt:
                    all_samples.append((txt, "safe", "afrisenti_nigerian"))
                    safe_count += 1
        print(f"    Loaded {safe_count} safe Nigerian Pidgin English text samples.")
    except Exception as e:
        print(f"    [-] Failed to process afrisenti: {e}")

    # 3. ucirvine/sms_spam
    try:
        print("[+] Loading ucirvine/sms_spam...")
        ds = load_dataset("ucirvine/sms_spam", split="train")
        safe_count = 0
        phish_count = 0
        for item in ds:
            txt = clean_text(item["sms"])
            if not txt:
                continue
            # label 0 = ham, 1 = spam
            if item["label"] == 0 and safe_count < target_safe:
                all_samples.append((txt, "safe", "sms_spam_hf"))
                safe_count += 1
            elif item["label"] == 1 and phish_count < target_phishing:
                all_samples.append((txt, "phishing", "sms_spam_hf"))
                phish_count += 1
        print(f"    Loaded {safe_count} safe and {phish_count} spam SMS from HF.")
    except Exception as e:
        print(f"    [-] Failed to process ucirvine/sms_spam: {e}")

    # 4. wangyuancheng/discord-phishing-scam
    try:
        print("[+] Loading wangyuancheng/discord-phishing-scam...")
        ds = load_dataset("wangyuancheng/discord-phishing-scam", split="train")
        safe_count = 0
        phish_count = 0
        for item in ds:
            txt = clean_text(item["msg_content"])
            if not txt:
                continue
            # lable 0 = safe, 1 = phishing
            if item["lable"] == 0 and safe_count < target_safe:
                all_samples.append((txt, "safe", "discord_scam_hf"))
                safe_count += 1
            elif item["lable"] == 1 and phish_count < target_phishing:
                all_samples.append((txt, "phishing", "discord_scam_hf"))
                phish_count += 1
        print(f"    Loaded {safe_count} safe and {phish_count} phishing Discord messages from HF.")
    except Exception as e:
        print(f"    [-] Failed to process discord-phishing-scam: {e}")

    # 5. MOZNLP/MOZ-Smishing
    try:
        print("[+] Loading MOZNLP/MOZ-Smishing...")
        ds = load_dataset("MOZNLP/MOZ-Smishing", split="test")
        safe_count = 0
        phish_count = 0
        for item in ds:
            txt = clean_text(item["text"])
            if not txt:
                continue
            # label 'Legitimate' or 'Smishing'
            if item["label"] == 'Legitimate' and safe_count < target_safe:
                all_samples.append((txt, "safe", "moz_smishing_hf"))
                safe_count += 1
            elif item["label"] == 'Smishing' and phish_count < target_phishing:
                all_samples.append((txt, "phishing", "moz_smishing_hf"))
                phish_count += 1
        print(f"    Loaded {safe_count} safe and {phish_count} smishing SMS from HF.")
    except Exception as e:
        print(f"    [-] Failed to process MOZ-Smishing: {e}")


    # ----------------- LOCAL CSV DATASETS -----------------
    print("\n--- Processing Local CSV Datasets ---")
    dataset_dir = "Dataset"
    
    if not os.path.exists(dataset_dir):
        print(f"[-] Error: Dataset directory '{dataset_dir}' does not exist.")
        return

    csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv') and f != "emails.csv"]
    
    for csv_file in csv_files:
        path = os.path.join(dataset_dir, csv_file)
        name = csv_file.split(".")[0]
        try:
            print(f"[+] Processing {csv_file}...")
            # Load file in latin-1 to avoid decoding issues
            df = pd.read_csv(path, encoding="latin-1")
            
            # Auto-detect content and label columns
            text_col = None
            label_col = None
            
            # Find label column
            for col in df.columns:
                if col.lower() in ["label", "class", "v1", "scam_type", "category"]:
                    label_col = col
                    break
            
            # Find text/body/message column
            for col in df.columns:
                if col.lower() in ["body", "text", "v2", "message", "text_combined", "msg_content", "url"]:
                    text_col = col
                    break
            if text_col is None and "subject" in [c.lower() for c in df.columns]:
                text_col = "subject"
                
            if not text_col:
                print(f"    [-] Warning: Could not detect text column in {csv_file}. Columns: {df.columns.tolist()}")
                continue
                
            # Parse rows
            safe_count = 0
            phish_count = 0
            
            # Let's adjust target sizes for some special files
            local_target_phish = target_phishing
            local_target_safe = target_safe
            if name == "Nigerian_Fraud":
                local_target_phish = 250 # Increase representation of Nigerian scam emails
                local_target_safe = 0
            elif name in ["Nazario", "whatsapp_scam_dataset", "urls"]:
                local_target_safe = 0
            elif name == "Enron":
                local_target_phish = 0
                local_target_safe = 250
            
            # Shuffle dataframe rows to get diverse samples
            df = df.sample(frac=1).reset_index(drop=True)
            
            for _, row in df.iterrows():
                # Formulate text
                txt = ""
                if "subject" in [c.lower() for c in df.columns] and text_col != "subject":
                    subject = str(row.get("subject", ""))
                    body = str(row.get(text_col, ""))
                    if subject and subject.lower() != "nan":
                        txt = f"Subject: {subject}\n\n{body}"
                    else:
                        txt = body
                else:
                    txt = str(row.get(text_col, ""))
                
                txt = clean_text(txt)
                if not txt:
                    continue
                
                # Formulate label
                label_val = str(row.get(label_col, "0")) if label_col else "1"
                label_val_lower = label_val.lower().strip()
                
                is_phishing = False
                if label_col:
                    if label_val_lower in ["1", "spam", "phishing", "scamming", "malware", "yes", "true"]:
                        is_phishing = True
                    elif name == "whatsapp_scam_dataset" and label_val_lower != "nan":
                        # whatsapp_scam_dataset has scam subcategories as labels, which all mean scam
                        is_phishing = True
                else:
                    # Default if no label col: check file context
                    if name in ["Nazario", "Nigerian_Fraud", "whatsapp_scam_dataset", "urls"]:
                        is_phishing = True
                
                if is_phishing and phish_count < local_target_phish:
                    all_samples.append((txt, "phishing", name))
                    phish_count += 1
                elif not is_phishing and safe_count < local_target_safe:
                    all_samples.append((txt, "safe", name))
                    safe_count += 1
                    
                if phish_count >= local_target_phish and safe_count >= local_target_safe:
                    break
                    
            print(f"    Successfully ingested {safe_count} safe and {phish_count} phishing/scam samples.")
            
        except Exception as e:
            print(f"    [-] Failed to process {csv_file}: {e}")

    # 🚀 Assemble, Shuffle and Write to Output
    print(f"\n[+] Total raw training records gathered: {len(all_samples)}")
    
    # Perform standard class balance check
    phish_total = sum(1 for s in all_samples if s[1] == "phishing")
    safe_total = sum(1 for s in all_samples if s[1] == "safe")
    print(f"    Phishing/Scam Samples: {phish_total}")
    print(f"    Safe/Normal Samples: {safe_total}")
    
    print("[+] Shuffling and formatting into Gemini Tuning format...")
    random.shuffle(all_samples)
    
    tuning_data = []
    for txt, label, source in all_samples:
        # Check if the text contains a link and generate warnings for realistic simulations
        warnings = None
        if label == "phishing" and ("http" in txt or "www" in txt or ".com" in txt or ".net" in txt):
            warnings = ["The link contains a potential typosquatted lookalike of a trusted brand."]
        
        sample = format_sample(txt, label, source, warnings)
        tuning_data.append(sample)
        
    # Write to gemini_tuning_data.jsonl
    output_path = "gemini_tuning_data.jsonl"
    with open(output_path, "w", encoding="utf-8") as f:
        for item in tuning_data:
            f.write(json.dumps(item) + "\n")
            
    print(f"[+] Successfully generated {output_path} with {len(tuning_data)} high-fidelity examples!")

if __name__ == "__main__":
    main()
