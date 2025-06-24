import argparse
import random
import subprocess

from vm_lib import root_dir


TEMPLATE_DATA = (root_dir / 'linker.ld.template').read_text()
OUT_PATH = root_dir / 'linker.ld'


def get_functions_from_object_file(obj_file: str) -> list[str]:
    functions = set()

    cmd = ['readelf', '-S', '--wide', obj_file]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    for line in result.stdout.splitlines():
        if not line.strip().startswith('[') or ']' not in line:
            continue
        name = line.split(']')[1].split()[0]
        if not name.startswith('.text.'):
            continue
        functions.add(name)

    return list(functions)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('object_files', nargs='+')

    args = parser.parse_args()
    all_function_sections = ['.text._start']

    for obj_file_raw in args.object_files:
        for obj_file in obj_file_raw.split(';'):
            all_function_sections.extend(get_functions_from_object_file(obj_file))

    random.shuffle(all_function_sections)
    function_order_text = '\n'.join([' ' * 8 + f'KEEP(*({func_section}))' for func_section in all_function_sections])

    template_content = TEMPLATE_DATA.replace('/* FUNCTIONS */', function_order_text)
    OUT_PATH.write_text(template_content)
