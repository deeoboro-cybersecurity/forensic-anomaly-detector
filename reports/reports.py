import os


def generate_human_readable_report(artifacts, output_path="output/report.txt"):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    total_size = sum(a.get("size", 0) for a in artifacts)
    anomaly_count = sum(1 for a in artifacts if a.get("is_anomaly"))

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write("===== Forensic Artifact Extraction Report =====\n\n")
        report_file.write(f"Total files scanned: {len(artifacts)}\n")
        report_file.write(f"Total size of files (bytes): {total_size}\n")
        report_file.write(f"Flagged as anomalous: {anomaly_count}\n")
        report_file.write("\n" + "=" * 50 + "\n\n")

        for i, a in enumerate(artifacts, start=1):
            flag = "  [ANOMALY]" if a.get("is_anomaly") else ""
            report_file.write(f"{i}. {a['path']}{flag}\n")
            report_file.write(f"   SHA256:        {a.get('hash', 'N/A')}\n")
            report_file.write(f"   Size:          {a.get('size', 'N/A')} bytes\n")
            report_file.write(f"   Created:       {a.get('created', 'N/A')}\n")
            report_file.write(f"   Modified:      {a.get('modified', 'N/A')}\n")
            report_file.write(f"   Accessed:      {a.get('accessed', 'N/A')}\n")
            report_file.write(f"   Anomaly score: {a.get('anomaly_score', 'N/A')}\n\n")

    return output_path