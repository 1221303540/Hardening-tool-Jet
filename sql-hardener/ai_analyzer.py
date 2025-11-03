import google.generativeai as genai

def get_executive_summary(findings_list, risk_score, total_findings, total_crit, total_warn, api_key, utils):
    """
    Uses the Gemini API to generate a high-level summary of the findings.
    """
    write_to_file = utils.write_to_file
    
    # Only try to run if there are findings to report
    critical_findings = [f for f in findings_list if "[CRIT]" in f or "[WARN]" in f]
    if not critical_findings:
        return "All checks passed. No high-risk issues found."

    try:
        # Validate API key
        if not api_key or not api_key.strip():
            write_to_file("\n[AI_ERROR] API key is empty or invalid.")
            return "AI summary could not be generated. Invalid API key."
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('models/gemini-2.5-flash')

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
         {findings_text}\

        Your task is to generate a 3-part executive summary in plain English. Avoid all technical jargon.

        
        1.  **Overall Risk Assessment:** Start with a single, clear classification: CRITICAL, HIGH, MEDIUM, or LOW. Address each findings in a tone as short as possible.
        2.  **Key Risk Narrative:** Do not list all findings. Instead, identify the single most urgent attack vector. Explain *how* 2-3 of the findings *combine* to create a specific business risk (e.g., "Attackers can steal customer data because...") in short and concise terms.
        3.  **Priority Action Plan:** List the urgent remediation steps from most urgent to non-urgent in a numbered list. Be short andspecific.

        Technical Findings:
        {findings_text}
        """

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        write_to_file(f"\n[AI_ERROR] Could not generate AI summary: {e}")
        return "AI summary could not be generated. Please check API key and connectivity."