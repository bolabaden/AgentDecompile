class CLI:
    def __init__(self):
        self.parser = self.create_parser()

    def create_parser(self):
        import argparse
        parser = argparse.ArgumentParser(description="Agent Decompile Command Line Interface")
        parser.add_argument('command', choices=['analyze', 'help'], help='Command to execute')
        parser.add_argument('--input', type=str, help='Input file for analysis')
        parser.add_argument('--output', type=str, help='Output file for results')
        return parser

    def execute(self, args):
        parsed_args = self.parser.parse_args(args)
        if parsed_args.command == 'analyze':
            self.analyze(parsed_args.input, parsed_args.output)
        elif parsed_args.command == 'help':
            self.parser.print_help()

    def analyze(self, input_file, output_file):
        from .core import Core
        core = Core()
        results = core.process_data(input_file)
        with open(output_file, 'w') as f:
            f.write(results)