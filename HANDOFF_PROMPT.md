# VAPT-AI - AI Handoff Prompt
# Copy paste this ENTIRE file to new AI chat session

## CONTEXT:
Main ek VAPT-AI tool bana raha hoon - autonomous penetration testing 
aur bug bounty CLI tool. Python + LangChain + LangGraph based hai.
Tu mera coding partner hai. Tujhe code likhna hai, debug karna hai.

## TECH STACK:
- Python 3.10+, LangChain, LangGraph
- CLI Dashboard: Rich + Textual library
- LLM Providers: NVIDIA Build (free), Groq (free), Gemini (free), Ollama (local)
- Security Tools: nmap, nuclei, sqlmap, ffuf, nikto, subfinder, httpx, etc.
- OS: Windows WSL2 Kali Linux, 16GB RAM, RTX 3050 6GB

## ARCHITECTURE:
5 AI Agents in pipeline:
1. RECON Agent → Information gathering
2. ANALYZER Agent → Vulnerability analysis  
3. PLANNER Agent → Attack strategy
4. EXECUTOR Agent → Run attacks
5. REPORTER Agent → Generate reports

Smart LLM Router automatically picks best free model per task.

## COMPLETED:
[List completed modules with file names]

## CURRENT ERROR/ISSUE:
[Paste any current error]

## WHAT I NEED NOW:
[Write what you need - next module code, bug fix, etc.]

## KEY FILES FOR REFERENCE:
[Paste relevant file contents if needed]