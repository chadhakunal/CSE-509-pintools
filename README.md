# README for BackwardEdgeCFI Pin Tool

## Instructions for Setting Up and Using the BackwardEdgeCFI Pin Tool

### 1. Download Pin Tools for Linux
Download the Pin framework for Linux from the official Intel Pin website:
- [Intel Pin Downloads](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html)

### 2. Extract and Save to Home Directory
Once the download is complete:
1. Extract the tar file:
   ```bash
   tar -xvf pin-*.tar.gz
   ```
2. Move the extracted folder to your home directory for convenience:
   ```bash
   mv pin-<version> ~/pinkit
   ```
   Replace `<version>` with the actual version of Pin you downloaded.

### 3. Navigate to the Project Directory
Change directory to the location of the `CSE-509-pintools` repository:
```bash
cd /path/to/CSE-509-pintools
```
Replace `/path/to` with the actual path to the project directory.

### 4. Build the Pin Tool
Set the `PIN_ROOT` environment variable to the path of your Pin kit and build the tool:
```bash
PIN_ROOT=~/pinkit make
```
This will compile the `BackwardEdgeCFI` tool and create a shared object file (`BackwardEdgeCFI.so`) in the `obj-intel64` directory.

### 5. Run the Pin Tool
To use the `BackwardEdgeCFI` tool on an application, run the following command:
```bash
~/pinkit/pin -t obj-intel64/BackwardEdgeCFI.so -- <application_name>
```
- Replace `<application_name>` with the executable you want to analyze.
- Ensure the application is accessible from the current directory or provide the full path.

### Example
For example, to instrument the `ls` command:
```bash
~/pinkit/pin -t obj-intel64/BackwardEdgeCFI.so -- /bin/ls
```

### Notes
- Ensure you have `make` and `g++` installed on your system.
- If you encounter issues during compilation or runtime, verify that the Pin kit is compatible with your system architecture (e.g., x86-64).

For further assistance, refer to the Pin documentation or contact your course instructor.

