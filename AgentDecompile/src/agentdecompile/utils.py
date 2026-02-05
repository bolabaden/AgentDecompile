def format_data(data):
    # Function to format data for output
    return str(data)

def validate_input(input_data):
    # Function to validate input data
    if not input_data:
        raise ValueError("Input data cannot be empty")
    return True

def parse_file(file_path):
    # Function to parse a file and return its contents
    with open(file_path, 'r') as file:
        return file.read()