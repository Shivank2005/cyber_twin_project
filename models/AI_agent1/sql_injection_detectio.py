import pandas as pd
import os

_sql_cache = None

def check_payload_sql(payload):
    payload = str(payload).upper()
    
    # More robust signature matching
    patterns = [
        "OR 1=1", 
        "DROP TABLE", 
        "UNION SELECT", 
        "--", 
        "OR '1'='1", 
        r"OR \'1\'=\'1",
        "XP_CMDSHELL", 
        "INFORMATION_SCHEMA"
    ]
    
    # Strip spaces to prevent obfuscation bypasses: "OR   '1'  =  '1'" 
    stripped_payload = payload.replace(" ", "")
    
    for pattern in patterns:
        if pattern in payload:
            return True
        # Also check without spaces
        if pattern.replace(" ", "") in stripped_payload:
            return True
        # Also strip single quotes just in case the attacker escapes them strangely
        if pattern.replace("'", "") in stripped_payload.replace("'", ""):
            return True
    return False

def run_sql_model():
    global _sql_cache
    if _sql_cache is not None:
        return _sql_cache

    file_path = os.path.join(os.path.dirname(__file__), "advanced_generated_sql_injections.csv")
    data = pd.read_csv(file_path)

    # Improved detection logic (more realistic)
    patterns = [
        "OR 1=1",
        "DROP TABLE",
        "UNION SELECT",
        "--",
        "' OR '1'='1",
        "xp_cmdshell",
        "information_schema"
    ]

    def detect_sql(payload):
        payload = str(payload).upper()
        for pattern in patterns:
            if pattern in payload:
                return "SQL Injection Detected 🚨"
        return "Safe ✅"

    data["Result"] = data["Payload"].apply(detect_sql)

    # Return multiple results for demo
    _sql_cache = data[["Payload", "Result"]].head(10).to_dict(orient="records")
    return _sql_cache