# API Scan Tool

This Python script scans a specified API endpoint for vulnerabilities by testing various directories and parameters. The results are compiled into a report that can help identify potential security issues.

## Features

- Directory and parameter scanning based on provided wordlists.
- Generates a report of the scan results.
- Email notifications for scan results.

## Requirements

Make sure you have Python 3.x installed on your machine. You will also need to install the required packages listed in `requirements.txt`. Additionally, this tool utilizes `ffuf` and `x8`, so please ensure these tools are installed on your system.

### Installation

1. Clone this repository:

   ```
   git clone https://github.com/yourusername/api-scan.git
   cd api-scan
   ```

2. Install the required Python packages:

   ```
   pip install -r requirements.txt
   ```

3. Install `ffuf`:

   - For installation instructions, please visit the [ffuf GitHub repository](https://github.com/ffuf/ffuf).

4. Install `x8`:

   - For installation instructions, please visit the [x8 GitHub repository](https://github.com/Sh1Yo/x8).

## Usage

Run the script using the following command:

```
python api-scan.py -u <API_URL> -w <DIRECTORY_WORDLIST> -p <PARAMETER_WORDLIST>
```

### Parameters

- `-u` or `--urls`: The base URL of the API you want to scan.
- `-w` or `--wordlist`: Path to the directory wordlist file.
- `-p` or `--param`: Path to the parameter wordlist file.

### Example

```
python api-scan.py -u http://127.0.0.1:8000/api -w directory.txt -p param.txt
```

## Output

The script will output the results of the scan to the console and send an email notification with the report. Ensure you configure the email settings in the script before running it.

## Credits

- This tool was inspired by the need for effective API vulnerability scanning.
- Special thanks to the developers of [ffuf](https://github.com/ffuf/ffuf) and [x8](https://github.com/Sh1Yo/x8) for their contributions to the security community.

## Contributing

If you would like to contribute to this project, please fork the repository and submit a pull request. We welcome contributions of any kind!

## Author

[Rafi](https://github.com/rafipiun)
