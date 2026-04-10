import os
from advisory_gen import CTIWorkbench
def main():
    # Entry point for the application
    tool = CTIWorkbench()
    target = input("Paste TI URL: ").strip()

    # Ask user for report type
    print("\nChoose report type:")
    print("1. Full Advisory (includes MITRE analysis, summary, IOCs)")
    print("2. Only IOCs (malicious indicators only)")
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "1":
        report_type = "full"
    elif choice == "2":
        report_type = "ioc"
    else:
        print("Invalid choice. Defaulting to Full Advisory.")
        report_type = "full"

    norm_url = tool._normalize_url(target)
    existing_report = tool.url_report_index.get(norm_url, {}).get("reports", {}).get(report_type)
    reuse_choice = None

    if existing_report and os.path.exists(existing_report):
        print(f"\nThis URL was already analyzed. Existing {report_type} report: {existing_report}")
        print("Choose an option:")
        print("1. Use existing report")
        print("2. Regenerate report using cached IOC data")
        print("3. Regenerate and force IOCs re-analysis")
        reuse_choice = input("Enter 1, 2 or 3: ").strip()

        if reuse_choice == "1":
            print(f"\n[+] Reusing existing report: {existing_report}")
            return
        elif reuse_choice not in {"2", "3"}:
            print("Invalid choice. Defaulting to regenerate using cached IOC data.")
            reuse_choice = "2"

    result = tool.generate_report(target, report_type=report_type, reuse_choice=reuse_choice)
    if result == "NO IOC Found":
        print("\n[!] No IOCs were found for this URL; no IOC-only report was created.")
    elif result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")


if __name__ == "__main__":
    main()

 # The main block serves as the entry point for the script when executed directly.
# It prompts the user to input a Threat Intelligence (TI) URL, then calls the generate_report method of the CTIWorkbench class to analyze the URL and produce a report.
# The result of the analysis is printed to the console, indicating success or failure. If the execution fails, it advises the user to check the log file for more details.