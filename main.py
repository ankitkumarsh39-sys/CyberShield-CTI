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