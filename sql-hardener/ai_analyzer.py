import google.generativeai as genai

def get_executive_summary(findings_list, api_key, utils):
    """
    Uses the Gemini API to generate a high-level summary of the findings.
    """
    write_to_file = utils.write_to_file
    
    # Only try to run if there are findings to report
    critical_findings = [f for f in findings_list if "[CRIT]" in f or "[WARN]" in f]
    if not critical_findings:
        return "All checks passed. No high-risk issues found."

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('models/gemini-2.5-flash')

        # Create a clean list of findings for the prompt
        findings_text = "\n".join(critical_findings)

        prompt = f"""
        You are a senior cybersecurity auditor writing an executive summary for a non-technical manager.
        Below is a list of technical security findings from an automated database scan.
        
        Do the following:
        1.  Start with a 1-sentence "bottom line" of the server's security (e.g., "Critical", "Needs Attention", etc.).
        2.  In 2-3 sentences, describe the *most urgent combined risks* in simple terms.
        3.  Do not list every finding. Summarize the main themes.
        
        Technical Findings:
        {findings_text}
        """

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        write_to_file(f"\n[AI_ERROR] Could not generate AI summary: {e}")
        return "AI summary could not be generated. Please check API key and connectivity."