import logging

def prioritize_vulns(risk_scores):
    logging.info("Prioritizing vulnerabilities...")
    prioritized = {}
    for port, vulns in risk_scores.items():
        prioritized[port] = sorted(vulns.items(), key=lambda item: item[1], reverse=True)
    logging.info(f"Prioritized vulnerabilities: {prioritized}")
    return prioritized

if __name__ == "__main__":
    from initialize import load_config, setup_logging
    setup_logging()
    # Mock data for testing
    risk_scores = {
        22: {'CVE-2020-1234': 9.8, 'CVE-2019-5678': 5.4},
        80: {'CVE-2021-8765': 7.5},
    }
    prioritized_vulns = prioritize_vulns(risk_scores)
    print(f"Prioritized Vulnerabilities: {prioritized_vulns}")
