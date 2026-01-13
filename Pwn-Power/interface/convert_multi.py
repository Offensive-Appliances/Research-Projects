import os

def file_to_c_array(filepath, var_name):
    with open(filepath, 'rb') as f:
        content = f.read()
    
    c_array = ', '.join(f'0x{byte:02X}' for byte in content)
    return f'''const unsigned int {var_name}_SIZE = {len(content)};
const unsigned char {var_name}[] = {{ {c_array} }};
'''

def generate_web_content():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, '..', 'main')
    
    files = [
        ('index_new.html', 'INDEX_HTML'),
        ('styles.css', 'STYLES_CSS'),
        ('app.js', 'APP_JS'),
    ]
    
    header_content = '''#ifndef WEB_CONTENT_H
#define WEB_CONTENT_H

'''
    source_content = '''#include "web_content.h"

'''
    
    for filename, var_name in files:
        filepath = os.path.join(script_dir, filename)
        if os.path.exists(filepath):
            header_content += f'extern const unsigned int {var_name}_SIZE;\n'
            header_content += f'extern const unsigned char {var_name}[];\n\n'
            source_content += file_to_c_array(filepath, var_name) + '\n'
            print(f"Processed: {filename} -> {var_name}")
        else:
            print(f"Warning: {filename} not found")
    
    header_content += '#endif\n'
    
    header_path = os.path.join(output_dir, 'web_content.h')
    source_path = os.path.join(output_dir, 'web_content.c')
    
    with open(header_path, 'w') as f:
        f.write(header_content)
    print(f"Created: {header_path}")
    
    with open(source_path, 'w') as f:
        f.write(source_content)
    print(f"Created: {source_path}")

if __name__ == "__main__":
    generate_web_content()
