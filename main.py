from datetime import datetime

def monitoring_agent():
    print("\n[Monitoring Agent] Collecting security events...")
    return [
        {"event": "Suspicious process execution", "ip": "192.168.1.25", "severity": "High"},
        {"event": "Multiple failed login attempts", "ip": "192.168.1.40", "severity": "Medium"},
        {"event": "Normal user login", "ip": "192.168.1.30", "severity": "Low"},
        {"event": "Suspicious external connection", "ip": "192.168.1.50", "severity": "High"}
    ]

def detection_agent(events):
    print("\n[Detection Agent] Analysing events...")
    return [e for e in events if e["severity"] in ("High", "Medium")]

def investigation_agent(threats):
    print("\n[Investigation Agent] Investigating threats...")
    for t in threats:
        print(f"Event: {t['event']} | IP: {t['ip']} | Severity: {t['severity']}")

def decision_agent(threats):
    print("\n[Decision Agent] Prioritising threats...")
    if any(t["severity"] == "High" for t in threats):
        return "HIGH RISK"
    if threats:
        return "MEDIUM RISK"
    return "LOW RISK"

def response_agent(risk):
    print("\n[Response Agent] Preparing response...")
    actions = {
        "HIGH RISK": "Prioritise investigation and consider isolating the affected host.",
        "MEDIUM RISK": "Review the events and monitor for further suspicious activity.",
        "LOW RISK": "Continue routine monitoring."
    }
    print("Recommended Action:", actions[risk])

def main():
    print("=" * 45)
    print(" AUTONOMOUS MULTI-AGENT CYBER DEFENSE SYSTEM")
    print("=" * 45)

    events = monitoring_agent()
    threats = detection_agent(events)
    investigation_agent(threats)
    risk = decision_agent(threats)
    print("\nOverall Risk:", risk)
    response_agent(risk)
    print("\nExecution completed at", datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    main()
