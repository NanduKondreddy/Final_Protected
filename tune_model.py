import os
import json
import time
import dotenv
import google.generativeai as genai

def main():
    dotenv.load_dotenv()
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[-] Error: GEMINI_API_KEY is not set in the .env file.")
        return
        
    genai.configure(api_key=api_key)
    
    print("[+] Loading training dataset...")
    training_data = []
    
    if not os.path.exists("gemini_tuning_data.jsonl"):
        print("[-] Error: gemini_tuning_data.jsonl not found. Run prepare_tuning_data.py first.")
        return
        
    try:
        with open("gemini_tuning_data.jsonl", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    raw_item = json.loads(line)
                    # Extract user prompt and model response from contents format
                    contents = raw_item.get("contents", [])
                    text_input = ""
                    output = ""
                    for msg in contents:
                        role = msg.get("role")
                        parts = msg.get("parts", [])
                        txt = parts[0].get("text", "") if parts else ""
                        if role == "user":
                            text_input = txt
                        elif role == "model":
                            output = txt
                    
                    if text_input and output:
                        training_data.append({
                            "text_input": text_input,
                            "output": output
                        })
    except Exception as e:
        print(f"[-] Error loading dataset: {e}")
        return

    print(f"[+] Loaded {len(training_data)} training examples.")
    print("[+] Initiating Gemini fine-tuning job programmatically...")
    
    # Generate a unique suffix for the model name
    unique_suffix = f"shieldiq-detector-{int(time.time())}"
    
    try:
        # Launch the tuning job
        operation = genai.create_tuned_model(
            source_model="models/gemini-1.5-flash-001-tuning",
            training_data=training_data,
            id=unique_suffix,
            epoch_count=5,      # 5 epochs is perfect for 300 samples
            batch_size=4,
            learning_rate=0.001,
        )
        
        print("\n[+] Tuning job successfully submitted!")
        print(f"    Operation Name: {operation.name}")
        print("    Waiting for training to complete. This usually takes 3 to 10 minutes...")
        
        # Poll for completion status
        start_time = time.time()
        while not operation.done():
            elapsed = int(time.time() - start_time)
            print(f"    [Training] Elapsed: {elapsed}s | Still processing... (polling status)")
            time.sleep(30)
            operation.update()
            
        print("\n[+] 🎉 Tuning completed successfully!")
        result = operation.result()
        print(f"    Tuned Model ID: {result.name}")
        print("\n[+] NEXT STEP:")
        print(f"    Open your .env file and set: GEMINI_MODEL={result.name}")
        print("    Then restart the server to use your trained AI model!")
        
    except Exception as e:
        print(f"\n[-] Tuning job failed: {e}")
        print("    Check if your API key has tuning permissions enabled, or try reducing the training size.")

if __name__ == "__main__":
    main()
