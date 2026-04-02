from advisory_gen import CTIWorkbench
def main():
    # Entry point for the application
    tool = CTIWorkbench()
    target = input("Paste TI URL: ")
    result = tool.generate_report(target)
    if result:
        print(f"\n[+] Success: {result}")
    else:
        print("\n[!] Execution failed. Check cyber_shield.log for details.")


if __name__ == "__main__":
    main()

 # The main block serves as the entry point for the script when executed directly.
# It prompts the user to input a Threat Intelligence (TI) URL, then calls the generate_report method of the CTIWorkbench class to analyze the URL and produce a report.
# The result of the analysis is printed to the console, indicating success or failure. If the execution fails, it advises the user to check the log file for more details.