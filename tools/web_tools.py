"""
VAPT-AI Web Security Tools
============================
LangChain-compatible tool wrappers for web security tools:
- ffuf (directory fuzzing)
- curl (HTTP requests)
- whatweb (tech detection)
- wafw00f (WAF detection)
- katana (web crawling)
- subfinder (subdomain enumeration)
- httpx (HTTP probing)
"""

from typing import Optional, Dict, Type
from pydantic import BaseModel, Field
from langchain_core.tools import BaseTool


# ============================================
# FFUF - Directory Fuzzer
# ============================================

class FfufInput(BaseModel):
    target_url: str = Field(description="Base URL to fuzz (e.g., http://target.com)")
    wordlist: str = Field(
        default="/usr/share/wordlists/dirb/common.txt",
        description="Path to wordlist file"
    )
    extra_args: str = Field(default="", description="Additional ffuf arguments")


class FfufTool(BaseTool):
    name: str = "ffuf_fuzzer"
    description: str = (
        "Fast web fuzzer for discovering hidden directories, files, and endpoints. "
        "Provide the base URL and it will append words from wordlist. "
        "Great for finding /admin, /backup, /api, .git, .env files etc."
    )
    args_schema: Type[BaseModel] = FfufInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target_url: str,
             wordlist: str = "/usr/share/wordlists/dirb/common.txt",
             extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("ffuf"):
            return "Error: ffuf not available"
        
        cmd = self.tool_engine.build_ffuf_command(
            target_url=target_url, wordlist=wordlist, extra_args=extra_args,
        )
        result = self.tool_engine.execute_command_sync(cmd, timeout=300, tool_name="ffuf")
        return f"FFUF Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target_url: str,
                    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                    extra_args: str = "") -> str:
        cmd = self.tool_engine.build_ffuf_command(target_url=target_url, wordlist=wordlist, extra_args=extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=300, tool_name="ffuf")
        return f"FFUF Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# CURL - HTTP Client
# ============================================

class CurlInput(BaseModel):
    url: str = Field(description="URL to request")
    method: str = Field(default="GET", description="HTTP method: GET, POST, PUT, DELETE, PATCH")
    data: Optional[str] = Field(default=None, description="POST/PUT data to send")
    headers: Optional[str] = Field(
        default=None,
        description="Headers as 'Key1: Value1, Key2: Value2' format"
    )
    extra_args: str = Field(default="", description="Additional curl arguments")


class CurlTool(BaseTool):
    name: str = "curl_request"
    description: str = (
        "Make HTTP requests to any URL. Supports all HTTP methods (GET, POST, PUT, DELETE). "
        "Use this to interact with web applications, test APIs, send payloads, "
        "check response headers, and verify vulnerabilities manually."
    )
    args_schema: Type[BaseModel] = CurlInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, url: str, method: str = "GET", data: str = None,
             headers: str = None, extra_args: str = "") -> str:
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        
        # Parse headers string to dict
        headers_dict = {}
        if headers:
            for h in headers.split(","):
                if ": " in h:
                    k, v = h.strip().split(": ", 1)
                    headers_dict[k] = v

        cmd = self.tool_engine.build_curl_command(
            url=url, method=method, headers=headers_dict,
            data=data, extra_args=extra_args,
        )
        result = self.tool_engine.execute_command_sync(cmd, timeout=60, tool_name="curl")
        
        if result.success:
            # Truncate very long responses
            output = result.stdout
            if len(output) > 5000:
                output = output[:5000] + "\n\n... [TRUNCATED - Response too long] ..."
            return f"HTTP Response:\n{output}"
        return f"Request failed: {result.stderr}"

    async def _arun(self, url: str, method: str = "GET", data: str = None,
                    headers: str = None, extra_args: str = "") -> str:
        headers_dict = {}
        if headers:
            for h in headers.split(","):
                if ": " in h:
                    k, v = h.strip().split(": ", 1)
                    headers_dict[k] = v

        cmd = self.tool_engine.build_curl_command(
            url=url, method=method, headers=headers_dict, data=data, extra_args=extra_args,
        )
        result = await self.tool_engine.execute_command(cmd, timeout=60, tool_name="curl")
        output = result.stdout[:5000] if result.success else result.stderr
        return f"HTTP Response:\n{output}" if result.success else f"Failed: {output}"


# ============================================
# WHATWEB - Technology Detection
# ============================================

class WhatwebInput(BaseModel):
    target: str = Field(description="Target URL for technology detection")
    aggression: int = Field(default=3, description="Aggression level (1-4)")


class WhatwebTool(BaseTool):
    name: str = "whatweb_detector"
    description: str = (
        "Detect web technologies used by a website including CMS, frameworks, "
        "programming languages, web servers, JavaScript libraries, and more. "
        "Essential for understanding the tech stack before testing."
    )
    args_schema: Type[BaseModel] = WhatwebInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, aggression: int = 3) -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("whatweb"):
            return "Error: whatweb not available"
        cmd = self.tool_engine.build_whatweb_command(target, aggression)
        result = self.tool_engine.execute_command_sync(cmd, timeout=120, tool_name="whatweb")
        return f"WhatWeb Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target: str, aggression: int = 3) -> str:
        cmd = self.tool_engine.build_whatweb_command(target, aggression)
        result = await self.tool_engine.execute_command(cmd, timeout=120, tool_name="whatweb")
        return f"WhatWeb Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# WAFW00F - WAF Detection
# ============================================

class Wafw00fInput(BaseModel):
    target: str = Field(description="Target URL to check for WAF")


class Wafw00fTool(BaseTool):
    name: str = "waf_detector"
    description: str = (
        "Detect if a Web Application Firewall (WAF) is protecting the target. "
        "Identifies the WAF vendor (Cloudflare, Akamai, ModSecurity, etc.). "
        "Important to know before sending attack payloads - you may need bypass techniques."
    )
    args_schema: Type[BaseModel] = Wafw00fInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str) -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("wafw00f"):
            return "Error: wafw00f not available"
        cmd = self.tool_engine.build_wafw00f_command(target)
        result = self.tool_engine.execute_command_sync(cmd, timeout=60, tool_name="wafw00f")
        return f"WAF Detection:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target: str) -> str:
        cmd = self.tool_engine.build_wafw00f_command(target)
        result = await self.tool_engine.execute_command(cmd, timeout=60, tool_name="wafw00f")
        return f"WAF Detection:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# SUBFINDER - Subdomain Enumeration
# ============================================

class SubfinderInput(BaseModel):
    domain: str = Field(description="Domain to enumerate subdomains for (e.g., example.com)")
    extra_args: str = Field(default="", description="Additional subfinder arguments")


class SubfinderTool(BaseTool):
    name: str = "subdomain_finder"
    description: str = (
        "Discover subdomains of a domain using passive sources. "
        "Finds subdomains like api.example.com, admin.example.com, staging.example.com. "
        "Essential first step in reconnaissance to expand the attack surface."
    )
    args_schema: Type[BaseModel] = SubfinderInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, domain: str, extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("subfinder"):
            return "Error: subfinder not available"
        cmd = self.tool_engine.build_subfinder_command(domain, extra_args)
        result = self.tool_engine.execute_command_sync(cmd, timeout=120, tool_name="subfinder")
        return f"Subdomains Found:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, domain: str, extra_args: str = "") -> str:
        cmd = self.tool_engine.build_subfinder_command(domain, extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=120, tool_name="subfinder")
        return f"Subdomains Found:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# KATANA - Web Crawler
# ============================================

class KatanaInput(BaseModel):
    target: str = Field(description="Target URL to crawl")
    depth: int = Field(default=3, description="Crawling depth (1-5)")
    extra_args: str = Field(default="", description="Additional katana arguments")


class KatanaTool(BaseTool):
    name: str = "web_crawler"
    description: str = (
        "Crawl a web application to discover all URLs, endpoints, forms, "
        "and JavaScript files. Extracts links from HTML and JavaScript. "
        "Use this to map the full attack surface of the application."
    )
    args_schema: Type[BaseModel] = KatanaInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, depth: int = 3, extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("katana"):
            return "Error: katana not available"
        cmd = self.tool_engine.build_katana_command(target, depth, extra_args)
        result = self.tool_engine.execute_command_sync(cmd, timeout=180, tool_name="katana")
        return f"Crawled URLs:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target: str, depth: int = 3, extra_args: str = "") -> str:
        cmd = self.tool_engine.build_katana_command(target, depth, extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=180, tool_name="katana")
        return f"Crawled URLs:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# HTTPX - HTTP Probe
# ============================================

class HttpxInput(BaseModel):
    target: str = Field(description="URL or domain to probe")
    extra_args: str = Field(
        default="-sc -td -title -server -ct",
        description="httpx flags: -sc(status), -td(tech), -title, -server, -ct(content-type)"
    )


class HttpxTool(BaseTool):
    name: str = "http_probe"
    description: str = (
        "Fast HTTP toolkit to probe URLs and get status codes, technologies, "
        "titles, server info, and content types. Use this to quickly check "
        "which URLs are alive and what technologies they use."
    )
    args_schema: Type[BaseModel] = HttpxInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, extra_args: str = "-sc -td -title -server -ct") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("httpx"):
            return "Error: httpx not available"
        tool_path = self.tool_engine.tools["httpx"].path or "httpx"
        cmd = f"echo '{target}' | {tool_path} {extra_args} -silent"
        result = self.tool_engine.execute_command_sync(cmd, timeout=60, tool_name="httpx")
        return f"HTTPX Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target: str, extra_args: str = "-sc -td -title -server -ct") -> str:
        tool_path = self.tool_engine.tools["httpx"].path or "httpx"
        cmd = f"echo '{target}' | {tool_path} {extra_args} -silent"
        result = await self.tool_engine.execute_command(cmd, timeout=60, tool_name="httpx")
        return f"HTTPX Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# SQLMAP - SQL Injection
# ============================================

class SqlmapInput(BaseModel):
    target_url: str = Field(description="Target URL with parameter (e.g., http://target.com/page?id=1)")
    data: Optional[str] = Field(default=None, description="POST data (e.g., 'username=admin&password=test')")
    extra_args: str = Field(default="", description="Additional sqlmap arguments")


class SqlmapTool(BaseTool):
    name: str = "sqlmap_scanner"
    description: str = (
        "Automated SQL injection detection and exploitation tool. "
        "Provide a URL with parameters to test for SQL injection. "
        "Supports GET and POST requests. Use --batch flag to run non-interactively. "
        "Can detect and exploit: UNION, boolean-based, time-based, error-based SQLi."
    )
    args_schema: Type[BaseModel] = SqlmapInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target_url: str, data: str = None, extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("sqlmap"):
            return "Error: sqlmap not available"
        cmd = self.tool_engine.build_sqlmap_command(target_url, data, extra_args)
        result = self.tool_engine.execute_command_sync(cmd, timeout=300, tool_name="sqlmap")
        return f"SQLMap Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target_url: str, data: str = None, extra_args: str = "") -> str:
        cmd = self.tool_engine.build_sqlmap_command(target_url, data, extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=300, tool_name="sqlmap")
        return f"SQLMap Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# DALFOX - XSS Scanner
# ============================================

class DalfoxInput(BaseModel):
    target_url: str = Field(description="Target URL with parameter to test for XSS")
    extra_args: str = Field(default="", description="Additional dalfox arguments")


class DalfoxTool(BaseTool):
    name: str = "xss_scanner"
    description: str = (
        "XSS vulnerability scanner and parameter analyzer. "
        "Tests for reflected and stored XSS with various bypass techniques. "
        "Provide a URL with parameters to test."
    )
    args_schema: Type[BaseModel] = DalfoxInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target_url: str, extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("dalfox"):
            return "Error: dalfox not available"
        cmd = self.tool_engine.build_dalfox_command(target_url, extra_args)
        result = self.tool_engine.execute_command_sync(cmd, timeout=180, tool_name="dalfox")
        return f"DalFox XSS Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target_url: str, extra_args: str = "") -> str:
        cmd = self.tool_engine.build_dalfox_command(target_url, extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=180, tool_name="dalfox")
        return f"DalFox XSS Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# NIKTO - Web Server Scanner
# ============================================

class NiktoInput(BaseModel):
    target: str = Field(description="Target URL to scan")
    extra_args: str = Field(default="", description="Additional nikto arguments")


class NiktoTool(BaseTool):
    name: str = "nikto_scanner"
    description: str = (
        "Web server scanner that tests for dangerous files, outdated server software, "
        "misconfigurations, and other security issues. Comprehensive but can be slow."
    )
    args_schema: Type[BaseModel] = NiktoInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, target: str, extra_args: str = "") -> str:
        if not self.tool_engine or not self.tool_engine.is_tool_available("nikto"):
            return "Error: nikto not available"
        cmd = self.tool_engine.build_nikto_command(target, extra_args)
        result = self.tool_engine.execute_command_sync(cmd, timeout=600, tool_name="nikto")
        return f"Nikto Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"

    async def _arun(self, target: str, extra_args: str = "") -> str:
        cmd = self.tool_engine.build_nikto_command(target, extra_args)
        result = await self.tool_engine.execute_command(cmd, timeout=600, tool_name="nikto")
        return f"Nikto Results:\n{result.stdout}" if result.success else f"Failed: {result.stderr}"


# ============================================
# GENERIC COMMAND TOOL
# ============================================

class GenericCommandInput(BaseModel):
    command: str = Field(description="Shell command to execute")
    timeout: int = Field(default=120, description="Command timeout in seconds")


class GenericCommandTool(BaseTool):
    name: str = "shell_command"
    description: str = (
        "Execute any shell command on the system. Use this for custom commands, "
        "piping outputs, or running tools not covered by specific tool wrappers. "
        "Be careful with this tool - only run commands within authorized scope."
    )
    args_schema: Type[BaseModel] = GenericCommandInput
    tool_engine: object = None

    class Config:
        arbitrary_types_allowed = True

    def _run(self, command: str, timeout: int = 120) -> str:
        if not self.tool_engine:
            return "Error: Tool engine not initialized"
        result = self.tool_engine.execute_command_sync(
            command=command, timeout=timeout, tool_name="custom"
        )
        output = result.stdout if result.success else result.stderr
        if len(output) > 5000:
            output = output[:5000] + "\n... [TRUNCATED]"
        return f"Command Output:\n{output}"

    async def _arun(self, command: str, timeout: int = 120) -> str:
        result = await self.tool_engine.execute_command(
            command=command, timeout=timeout, tool_name="custom"
        )
        output = result.stdout if result.success else result.stderr
        if len(output) > 5000:
            output = output[:5000] + "\n... [TRUNCATED]"
        return f"Command Output:\n{output}"


# ============================================
# TOOL FACTORY
# ============================================

def create_all_tools(tool_engine) -> list:
    """Create all LangChain tools with the tool engine attached."""
    # Import tools from separate files
    from tools.nmap_tool import NmapTool
    from tools.nuclei_tool import NucleiTool

    tools = []

    tool_classes = [
        NmapTool,
        NucleiTool,
        SqlmapTool,
        FfufTool,
        CurlTool,
        WhatwebTool,
        Wafw00fTool,
        SubfinderTool,
        KatanaTool,
        HttpxTool,
        DalfoxTool,
        NiktoTool,
        GenericCommandTool,
    ]

    for tool_class in tool_classes:
        tool = tool_class()
        tool.tool_engine = tool_engine
        tools.append(tool)

    return tools