import joblib
import re
import streamlit as st

@st.cache_resource
def load_models():
    try:
        model = joblib.load("rf_model_all_obfuscations.pkl")
        vectorizer = joblib.load("vectorizer_all_obfuscations.pkl")
        return model, vectorizer
    except Exception as e:
        st.error(f"Error loading models: {e}. Ensure .pkl files are present.")
        return None, None

def is_valid_sql_query(query):
    query_upper = query.upper()
    primary_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'ALTER', 'CREATE']
    structural_keywords = ['FROM', 'INTO', 'SET', 'TABLE', 'WHERE', 'VALUES']
    has_primary = any(k in query_upper for k in primary_keywords)
    has_structural = any(k in query_upper for k in structural_keywords)
    return has_primary and has_structural

def check_rule_signatures(payload):
    sqli_patterns = [
        r"OR\s+\d+\s*=\s*\d+",
        r"OR\s+'[^']+'\s*=\s*'[^']+'",
        r"--",
        r";\s*DROP",
        r"UNION\s+SELECT",
        r"sleep\s*\(",
        r"create\s+or\s+replace"
    ]
    combined_pattern = "|".join(sqli_patterns)
    return bool(re.search(combined_pattern, payload, re.IGNORECASE))

def classify_payload(payload, rf_model, vectorizer):
    normalized = payload.lower()
    is_rule_hit = check_rule_signatures(payload)
    
    features = vectorizer.transform([normalized])
    pred = rf_model.predict(features)[0]
    prob = rf_model.predict_proba(features)[0][1] * 100.0
    
    if is_rule_hit:
        return "🚨 Attack", 100.0
    elif pred == 1 and prob >= 80.0:
        return "🚨 Attack", prob
    else:
        return "✅ Safe", prob