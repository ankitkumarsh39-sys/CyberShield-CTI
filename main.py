import os
from advisory_gen import CTIWorkbench

def choose_input_type():
    while True:
        print("Choose input type:")
        print("1. TI URL")
        print("2. Upload file with IOC (Excel / CSV / TXT / CVE)")
        print("3. Paste IOC/text directly")
        print("0. Exit")
        choice = input("Enter 1, 2, 3 or 0: ").strip()
        if choice == "1":
            return "url"
        if choice == "2":
            return "file"
        if choice == "3":
            return "paste"
        if choice == "0":
            return None
        print("Invalid choice. Please enter 1, 2, 3 or 0.\n")


def choose_report_type():
    while True:
        print("\nChoose report type:")
        print("1. Full Advisory (includes MITRE analysis and IOCs)")
        print("2. Only IOCs (malicious indicators only)")
        print("0. Exit")
        choice = input("Enter 1, 2 or 0: ").strip()
        if choice == "1":
            return "full"
        if choice == "2":
            return "ioc"
        if choice == "0":
            return None
        print("Invalid choice. Please enter 1, 2 or 0.\n")


def choose_vt_cache_behavior():
    while True:
        print("\nChoose VT cache behavior:")
        print("1. Use cached VT results when available")
        print("2. Force VT re-analysis for all IOCs")
        print("0. Exit")
        choice = input("Enter 1, 2 or 0: ").strip()
        if choice == "1":
            return "cache"
        if choice == "2":
            return "force_reanalysis"
        if choice == "0":
            return None
        print("Invalid choice. Please enter 1, 2 or 0.\n")


def choose_reuse_option(source_label, report_type, existing_report):
    print(f"\nThis {source_label} was already analyzed. Existing {report_type} report: {existing_report}")
    print("Choose an option:")
    print("1. Use existing report")
    print("2. Regenerate report using cached IOC data")
    print("3. Regenerate and force IOCs re-analysis")
    print("0. Exit")
    while True:
        choice = input("Enter 1, 2, 3 or 0: ").strip()
        if choice in {"1", "2", "3"}:
            return choice
        if choice == "0":
            return None
        print("Invalid choice. Please enter 1, 2, 3 or 0.\n")


def confirm_existing_analysis(target, is_file, tool):
    key = target if is_file else tool._normalize_url(target)
    report_info = tool.url_report_index.get(key, {})
    existing_reports = report_info.get("reports", {})
    valid_reports = {rt: rp for rt, rp in existing_reports.items() if os.path.exists(rp)}

    if not valid_reports:
        return True

    print(f"\nThis {'file' if is_file else 'URL'} has already been analyzed.")
    if report_info.get("last_analyzed"):
        print(f"Last analyzed: {report_info['last_analyzed']}")
    for report_type, report_path in valid_reports.items():
        print(f"Existing {report_type} report: {report_path}")
    if len(valid_reports) != len(existing_reports):
        print("Note: some previously recorded reports could not be found and will be ignored.")

    print("\nChoose an option:")
    print("1. Continue with analysis")
    print("0. Stop and exit")
    while True:
        choice = input("Enter 1 or 0: ").strip()
        if choice == "1":
            return True
        if choice == "0":
            return False
        print("Invalid choice. Please enter 1 or 0.\n")


def _read_pasted_input():
    print("\nPaste IOC/text below. Enter a blank line to finish:")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)
    content = "\n".join(lines).strip()
    if not content:
        print("No text entered. Exiting.")
        return None
    return content


def main():
    tool = CTIWorkbench()
    input_type = choose_input_type()
    if input_type is None:
        print("Exiting.")
        return

    if input_type == "file":
        target = input("Enter local file path: ").strip()
        if not os.path.isfile(target):
            print("File not found. Exiting.")
            return
    elif input_type == "url":
        target = input("Paste TI URL: ").strip()
        if not target:
            print("URL is required. Exiting.")
            return
    else:
        target = _read_pasted_input()
        if target is None:
            return

    if input_type != "paste":
        if not confirm_existing_analysis(target, input_type == "file", tool):
            print("Exiting.")
            return

        report_type = choose_report_type()
        if report_type is None:
            print("Exiting.")
            return

        vt_cache_mode = choose_vt_cache_behavior()
        if vt_cache_mode is None:
            print("Exiting.")
            return

        tool.vt_cache_prompt_mode = vt_cache_mode
    else:
        report_type = "ioc"
        tool.vt_cache_prompt_mode = "force_reanalysis"

    if input_type in {"file", "url"}:
        key = target if input_type == "file" else tool._normalize_url(target)
        existing_report = tool.url_report_index.get(key, {}).get("reports", {}).get(report_type)
        reuse_choice = None

        if existing_report and os.path.exists(existing_report):
            reuse_choice = choose_reuse_option("file" if input_type == "file" else "URL", report_type, existing_report)
            if reuse_choice is None:
                print("Exiting.")
                return
            if reuse_choice == "1":
                print(f"\n[+] Reusing existing report: {existing_report}")
                return

        print("\nNOTE: Press 'q' anytime during analysis to cancel.")
        result = tool.process_target(target, report_type=report_type, reuse_choice=reuse_choice)
    else:
        print("\nNOTE: Press 'q' anytime during analysis to cancel.")
        result = tool.generate_report_from_text(target, report_type=report_type)
    if result == "ANALYSIS_CANCELLED":
        print("\n[!] Analysis cancelled by user.")
    elif result == "NO IOC Found":
        if input_type == "file":
            source_label = "file"
        elif input_type == "url":
            source_label = "URL"
        else:
            source_label = "pasted text"
        print(f"\n[!] No IOCs were found for this {source_label}; no IOC-only report was created.")
    elif result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")


if __name__ == "__main__":
    main()
