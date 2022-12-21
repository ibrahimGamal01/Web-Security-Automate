import subprocess

# Define the terminal command as a string
command = "ls -l"

# Run the command using the subprocess module
output = subprocess.run(command.split(), stdout=subprocess.PIPE).stdout.decode('utf-8')

# Print the output of the command
print(output)
