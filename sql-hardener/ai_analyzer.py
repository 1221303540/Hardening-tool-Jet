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
        
        Quantitative Analysis:
        - Total Risk Score: {risk_score} (10 pts per Critical, 3 per Warning)
        - Total Findings: {total_findings}
        - Critical Findings: {total_crit}
        - Warning Findings: {total_warn}

        Technical Findings:
        {findings_text}

        Generate a 3-part executive summary in plain text format. Use simple, clear language without technical jargon.
        DO NOT use markdown symbols, asterisks, hashtags, or special formatting characters.
        
        Format the output as follows:
        
        Overall Risk Level: [State CRITICAL, HIGH, MEDIUM, or LOW]
        [Brief 2-3 sentence assessment]
        
        Key Risk:
        [Describe the most urgent attack vector and how findings combine to create business risk]
        
        Priority Actions:
        [List ALL necessary remediation actions based on the findings above]
        [Rank them from MOST URGENT to LEAST URGENT]
        [Use numbered list format: 1. action, 2. action, etc.]
        [Include every critical and warning finding that requires action]
        [Be specific and actionable for each item]
        
        Keep each action concise but complete.
        """

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        write_to_file(f"\n[AI_ERROR] Could not generate AI summary: {e}")
        return "AI summary could not be generated. Please check API key and connectivity."