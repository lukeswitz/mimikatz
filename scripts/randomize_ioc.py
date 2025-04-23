import os
import time
import re

def get_current_timestamp():
    return str(int(time.time()))

def replace_ioc_values(file_path, timestamp):
    with open(file_path, 'r') as file:
        content = file.read()

    # Replace IOC values with the current timestamp
    content = re.sub(r'IOC_VALUE', timestamp, content)

    with open(file_path, 'w') as file:
        file.write(content)

if __name__ == "__main__":
    timestamp = get_current_timestamp()
    target_files = [
        'mimikatz/mimikatz.c',
        'mimidrv/mimidrv.c',
        # Add other files that need IOC randomization here
    ]

    for file_path in target_files:
        replace_ioc_values(file_path, timestamp)
