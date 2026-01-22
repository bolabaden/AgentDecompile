import sys
from agentdecompile.core import Core

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze.py <data_file>")
        sys.exit(1)

    data_file = sys.argv[1]
    core = Core()

    # Load data
    data = core.load_data(data_file)

    # Perform analysis
    report = core.analyze_data(data)

    # Generate report
    core.generate_report(report)

if __name__ == "__main__":
    main()