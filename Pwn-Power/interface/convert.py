import os

def html_to_c_array(html_file):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Read the HTML content from the file
    with open(os.path.join(script_dir, html_file), 'rb') as f:
        html_content = f.read()

    # Create the C array representation
    c_array = ', '.join(f'0x{byte:02X}' for byte in html_content)
    c_array = '{ ' + c_array + ' }'

    # Return the array and the size
    return c_array, len(html_content)

def generate_header_and_source(html_file, output_dir):
    # We will now use a fixed name for the output files: "index_content"
    base_name = "index_content"

    # Convert the HTML file content to a C array
    c_array, content_size = html_to_c_array(html_file)

    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Prepare the paths for the output files relative to script location
    output_path = os.path.join(script_dir, output_dir)
    
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    header_file = os.path.join(output_path, f"{base_name}.h")
    source_file = os.path.join(output_path, f"{base_name}.c")

    # Generate the header file
    with open(header_file, 'w') as h_file:
        h_file.write(f'''#ifndef {base_name.upper()}_H
#define {base_name.upper()}_H

extern const unsigned int {base_name.upper()}_SIZE;
extern const unsigned char {base_name.upper()}[];

#endif
''')

    # Generate the source file
    with open(source_file, 'w') as c_file:
        c_file.write(f'''#include "{base_name}.h"

const unsigned int {base_name.upper()}_SIZE = {content_size};
const unsigned char {base_name.upper()}[] = {c_array};

// Define INDEX_SIZE
const unsigned int INDEX_SIZE = sizeof({base_name.upper()}_SIZE);
''')

    print(f"Header file created: {header_file}")
    print(f"Source file created: {source_file}")

def main():
    # Path to the HTML file you want to convert
    html_file = "index.html"  # Change this to the path of your HTML file

    # Directory to store the generated C and H files
    output_dir = "output"  # You can specify the output directory here

    # Generate the header and source files
    generate_header_and_source(html_file, output_dir)

if __name__ == "__main__":
    main()
