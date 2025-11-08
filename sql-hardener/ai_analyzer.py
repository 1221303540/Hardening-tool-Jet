import google.generativeai as genai
from typing import List, Any
from constants import DEFAULT_AI_TEMPERATURE, AI_MODEL_NAME, LEVEL_WARNING

def get_executive_summary(
    findings_list: List[str], 
    risk_score: int, 
    total_findings: int, 
    total_crit: int, 
    total_warn: int, 
    api_key: str, 
    utils: Any
) -> str:
    write_to_file = utils.write_to_file
    
    # Only try to run if there are findings to report
    critical_findings = [f for f in findings_list if "[CRIT]" in f or "[WARN]" in f]
    if not critical_findings:
        return "All checks passed. No high-risk issues found."

    try:
        # Validate API key
        if not api_key or not api_key.strip():
            write_to_file(f"\n[{LEVEL_WARNING}] API key is empty or invalid.")
            return "AI summary could not be generated. Invalid API key."
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(AI_MODEL_NAME)
        generation_config = {
            "temperature": DEFAULT_AI_TEMPERATURE,
        }

        # Create a clean list of findings for the prompt
        findings_text = "\n".join(critical_findings)

        prompt = f"""
        Act as a professional cybersecurity consultant reporting to a CISO.
        The following is a list of raw technical findings from an automated database scan.
        
        Here is the quantitative analysis:
        - Total Risk Score: {risk_score} (10 pts per Critical, 3 per Warning)
        - Total Findings: {total_findings}
        - Critical Findings: {total_crit}
        - Warning Findings: {total_warn}

        Here is the list of raw technical findings:
        {findings_text}

        Your task is to generate a 3-part executive summary in plain English. Avoid all technical jargon.

        
        1.  **Overall Risk Assessment:** Start with a single, clear classification: CRITICAL, HIGH, MEDIUM, or LOW. Address each findings in a tone as short as possible.
        2.  **Key Risk Narrative:** Do not list all findings. Instead, identify the single most urgent attack vector. Explain *how* 2-3 of the findings *combine* to create a specific business risk (e.g., "Attackers can steal customer data because...") in short and concise terms.
        3.  **Priority Action Plan:** List the urgent remediation steps from most urgent to non-urgent in a numbered list. Be short and specific.
       
        """

         # Pass the prompt to the API 
        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )

        # Print the token count for debugging
        try:
            # Prints the token count to the console, not to the final report
            token_count = response.usage_metadata.candidates_token_count
            write_to_file(f"[INFO] Summary generated using {token_count} tokens.")
        except Exception:
            # Failsafe in case metadata is not returned
            pass 

        return response.text

    except Exception as e:
        write_to_file(f"\n[{LEVEL_WARNING}] Could not generate AI summary: {e}")
        return "AI summary could not be generated. Please check API key and connectivity."