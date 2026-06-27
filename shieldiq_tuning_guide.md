# ShieldIQ Custom Model Fine-Tuning Guide
**Target Model:** Gemini 1.5 Flash  
**Dataset:** 5,467 High-Fidelity Examples (`gemini_tuning_data.jsonl`, 5.64 MB)

This guide covers what has been completed today, how to configure a billing-enabled key, options for running the training job, and how to activate your custom-trained intelligence in the codebase tomorrow.

---

## 📊 1. What We Did Today (Dataset Completed)
We successfully compiled a clean, balanced training dataset matching the 18-dataset specification document:

1. **Workspace Sync:** Copied the complete local `Dataset/` folder containing the Kaggle CSV files (whatsapp scams, 419 emails, Enron safelist, URLs, etc.) to the active workspace on the `D:` drive.
2. **Tabular Bank Fraud Integration:** Configured the pipeline to stream `electricsheepafrica/nigerian-banking-retail-transactions` from Hugging Face, formatting transactions into descriptive textual scenarios.
3. **Multilingual Baseline:** Integrated baseline tweets in **Nigerian Pidgin English**, **Yoruba**, **Hausa**, and **Igbo** from AfriSenti.
4. **Git LFS Downloads:** Fetched raw JSON datasets for `difraud/difraud` (phishing and SMS splits) and `ealvaradob/phishing-dataset`.
5. **Execution Optimization:** Added a slicing mechanism that shuffles dataframes and samples the target rows before iterating. This reduced the parsing time of large CSVs (like the 106MB `phishing_email.csv`) from several minutes to under 30 seconds.
6. **Output File:** Generated **`gemini_tuning_data.jsonl`** (5.64 MB, 5,467 items) with balanced `phishing` and `safe` labels.

---

## 🔑 2. Phase 1: Setup a Billing-Enabled API Key (Prerequisite)
Google restricts Gemini fine-tuning to accounts with active billing profiles to prevent resource abuse. **New Google Cloud accounts receive $300 in free credits**, which is more than enough to train this model for free.

### Step-by-Step Configuration:
1. Go to the **[Google Cloud Console](https://console.cloud.google.com/)**.
2. Log in with the Google Account that will manage the model.
3. Click on **Billing** from the left navigation and click **Add Billing Account** (sign up for the free trial to activate the $300 credits).
4. Create a new Google Cloud Project (e.g., `shieldiq-detection`).
5. Open the top search bar and search for **Generative Language API** (or **Vertex AI API**). Click **Enable**.
6. Search for **APIs & Services > Credentials**.
7. Click **Create Credentials > API Key**.
8. Copy your new API key.
9. Open the `.env` file in the project root and replace the first line:
   ```env
   GEMINI_API_KEY=your_billing_enabled_api_key_here
   ```

---

## 🚀 3. Phase 2: Tuning Execution Options
Because Google AI Studio sometimes hides or greys out the "Tuned models" option in certain regions, choose **one** of the three routes below to execute the training.

### ── Route A: Programmatic Python SDK (Recommended & Fastest) ──
Since we already have the dataset compiled and the script `tune_model.py` written in the workspace, you can trigger training directly from the terminal.

1. Ensure Python dependencies are installed in your virtual environment:
   ```powershell
   .\venv\Scripts\pip install google-generativeai python-dotenv
   ```
2. Make sure your billing-enabled API key is saved in `.env`.
3. Open your terminal in the project directory and run:
   ```powershell
   python -u tune_model.py
   ```
4. **What the script does:**
   * It loads the 5,467 dataset entries and maps them to SDK tuples `(text_input, output)`.
   * It initiates `genai.create_tuned_model(...)` targeting `models/gemini-1.5-flash-001-tuning`.
   * It polls the Google servers every 30 seconds and outputs the completion state.
   * Once finished, it prints your **Tuned Model ID** (e.g., `tunedModels/shieldiq-detector-xxxxxx`).

---

### ── Route B: Vertex AI Console (If Google AI Studio UI is Unavailable) ──
If the AI Studio UI is hidden, you can run the exact same tuning pipeline visually inside the Google Cloud Console.

1. Go to the **[Google Cloud Storage Console](https://console.cloud.google.com/storage/browser)**.
2. Click **Create Bucket**, name it uniquely (e.g., `shieldiq-tuning-data`), and choose a regional location (e.g., `us-central1`).
3. Upload your **`gemini_tuning_data.jsonl`** file directly to the bucket.
4. Search for **Vertex AI** in the top search bar and go to the Vertex AI dashboard.
5. In the left-hand menu under *Vertex AI*, click **Model Garden**.
6. Search for **Gemini 1.5 Flash** and click on it.
7. Click the **Tune** button.
8. Configure the Tuning Wizard:
   * **Base Model Version:** `gemini-1.5-flash-001`
   * **Dataset Path:** Select the `gemini_tuning_data.jsonl` file in your Cloud Storage bucket.
   * **Hyperparameters (Optional):** Set `Epochs = 5`, `Learning Rate multiplier = 1`.
   * **Destination:** Select the same region as your bucket (e.g., `us-central1`).
9. Click **Start Tuning**. The job will run in the background. When completed, the model will appear in your **Vertex AI Model Registry** dashboard.

---

### ── Route C: Google AI Studio UI (If Enabled/Accessible) ──
If the feature is enabled on your email account/region:
1. Go to **[Google AI Studio](https://aistudio.google.com/)**.
2. Click **Tuned models** on the left menu (or **Create tuned model**).
3. Select **Gemini 1.5 Flash** as the base model.
4. Click **Import** and upload `gemini_tuning_data.jsonl`.
5. Name the model and click **Tune**.

---

## 🛡️ 4. Phase 3: Post-Tuning Integration (FastAPI Activation)
Once training is complete and you have your model name (e.g., `tunedModels/shieldiq-detector-123456` or the Vertex resource name `projects/PROJECT_NUMBER/locations/us-central1/models/tunedModels/shieldiq-detector-123456`):

### Step 1: Update the Environment Configuration
Open your project's **`.env`** file and update the `GEMINI_MODEL` key to point to your new model:
```env
GEMINI_API_KEY=your_api_key
GEMINI_MODEL=tunedModels/shieldiq-detector-123456
```

### Step 2: Verify Codebase Connection
The existing backend code is already configured to read this environment variable dynamically. In `analyzer.py`:
* The core analysis loop loads the model using `genai.GenerativeModel(os.environ.get("GEMINI_MODEL", "gemini-1.5-flash"))`.
* By setting the `.env` value, the site automatically switches its AI classifier to your custom-trained model.

### Step 3: Run and Test the Application
1. In your terminal, start the FastAPI server:
   ```powershell
   .\venv\Scripts\uvicorn main:app --port 8001 --reload
   ```
2. Open your web browser and go to:
   ```
   http://127.0.0.1:8001
   ```
3. Submit a test message through the dashboard scanner (e.g., a simulated WhatsApp or bank transfer alert) and verify that the risk classification runs successfully using your new tuned weights. Check the terminal logs to ensure no connection exceptions are thrown.
