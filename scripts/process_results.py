import csv
import sys
from collections import defaultdict

csv.field_size_limit(sys.maxsize)

file_path = "waf-evaluation-report-2026-April-18-06-15-56.csv"  # Change this by the correct path to your CSV file

# Counters
stats = {
    "owasp": defaultdict(lambda: {"total": 0, "blocked": 0}),
    "community": defaultdict(lambda: {"total": 0, "blocked": 0}),
    "false-pos": {"total": 0, "passed": 0}
}

# Map categories to attack types
attack_map = {
    "xss-scripting": "XSS",
    "sql-injection": "SQLi",
    "rce-urlparam": "RCE",
    "path-traversal": "LFI",
    "community-xss": "XSS",
    "community-sqli": "SQLi",
    "community-rce": "RCE",
    "community-lfi": "LFI"
}

dedup = {}

with open(file_path, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)

    for row in reader:
        code = int(row["Response Code"])

        # Ignore error codes (500, 404) as they don't indicate if the attack was blocked or not
        if code == 500 or code == 404:
            continue

        #  unique key (Can be adjusted if needed, but this should cover most cases to avoid duplicates)
        key = (
            row["Payload"],
            row["Set"],
            row["Case"],
            row["Placeholder"],
            row["Encoder"]
        )

        if key not in dedup:
            dedup[key] = code
        else:
            if code == 403:
                dedup[key] = 403

for (payload, source, category, placeholder, encoder), code in dedup.items():
    is_blocked = (code == 403)
    is_bypass = not is_blocked

    # OWASP / COMMUNITY
    if source in ["owasp", "community"]:
        if category in attack_map:
            attack_type = attack_map[category]

            stats[source][attack_type]["total"] += 1
            if is_blocked:
                stats[source][attack_type]["blocked"] += 1

    # TRUE NEGATIVE
    if source == "false-pos":
        stats["false-pos"]["total"] += 1
        if is_bypass:
            stats["false-pos"]["passed"] += 1


#  Show results
def print_results():
    print("\n=== RESULTADOS ===\n")

    for source in ["owasp", "community"]:
        print(f"--- {source.upper()} ---")

        source_total = 0
        source_blocked = 0

        for attack, data in stats[source].items():
            total = data["total"]
            blocked = data["blocked"]

            pct = (blocked / total * 100) if total > 0 else 0
            print(f"{attack}: {pct:.2f}% bloqueado ({blocked}/{total})")

            source_total += total
            source_blocked += blocked

        source_pct = (source_blocked / source_total * 100) if source_total > 0 else 0
        print(f"\nResumen {source.upper()}: {source_pct:.2f}% ({source_blocked}/{source_total})\n")
        
    total_attacks = 0
    blocked_attacks = 0

    valid_attacks = {"XSS", "SQLi", "RCE", "LFI"}

    for source in ["owasp", "community"]:
        for attack, data in stats[source].items():
            if attack in valid_attacks:
                total_attacks += data["total"]
                blocked_attacks += data["blocked"]

    protection_rate = (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 0

    print("--- PROTECCIÓN GLOBAL ---")
    print(f"Protección: {protection_rate:.2f}% ({blocked_attacks}/{total_attacks})")

    # True negatives
    tn_total = stats["false-pos"]["total"]
    tn_passed = stats["false-pos"]["passed"]
    tn_pct = (tn_passed / tn_total * 100) if tn_total > 0 else 0

    print("\n--- TRUE NEGATIVES ---")
    print(f"Permitidos correctamente: {tn_pct:.2f}% ({tn_passed}/{tn_total})")

print_results()
