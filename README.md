# Minecraft RAT Scanner

A security tool that scans Minecraft JAR files to detect potential Remote Access Trojans (RATs) and other malicious code using machine learning. The system analyzes file characteristics and behavior patterns to identify potentially harmful mods or plugins.

## Features

- Scan Minecraft JAR files for potential RATs and malware
- Machine learning-based detection system
- Feature extraction from JAR files
- Safe mod verification
- Detailed scan reports
- Custom training dataset support

## Project Structure

```
.
├── .gitignore
├── README.md
├── dataset/                 # Dataset directory (not versioned)
├── dataset_logger.py       # Logging utilities for dataset generation
├── extract_features.py      # Feature extraction from logs
├── generate_dataset.py      # Dataset generation script
├── jar_features.csv         # Extracted JAR features
├── log_safe_mods.py         # Safe mod logging functionality
├── main.py                  # Main application entry point
├── ml/                      # Machine learning utilities
├── models/                  # Trained models (not versioned)
├── requirements.txt         # Python dependencies
├── scan_log.csv             # Log scan results
└── train_model.py           # Model training script
```

## Prerequisites

- Python 3.7+
- pip (Python package manager)
- Git (for version control)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/minecraft_backend.git
   cd minecraft_backend
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Scanning a JAR File
```bash
python main.py --file path/to/your/mod.jar
```

### Training the Detection Model
```bash
# Generate training dataset from known good and bad samples
python generate_dataset.py

# Train the machine learning model
python train_model.py
```

### Extracting Features from JAR
```bash
python extract_features.py --file path/to/your/mod.jar
```

### Viewing Scan Results
Scan results are saved in `scan_log.csv` for historical reference.

## Security Considerations

- Always run scans in a secure, isolated environment when testing potentially malicious files
- Keep the detection model updated with the latest threat intelligence
- The `dataset/` directory contains training data and should not be shared publicly
- The `models/` directory contains trained models and should be kept secure

## Contributing

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Notes

- The `dataset/` directory contains training data and is not versioned
- The `models/` directory contains trained models and is not versioned
- Always verify scan results with additional security tools
- False positives/negatives can occur - use this as part of a comprehensive security strategy
