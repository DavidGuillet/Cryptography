# Cryptography

Utilities and application to generate deterministic passwords from a secret. Supports **Passveurd** (domain-based) and **CryptoPass** (user@url-based) generation schemes, plus a PIN configuration helper.

## Project Structure

```
Cryptography/
├── src/                    # Core password generation library
│   └── PasswordGenerator.py
├── App/                    # Streamlit application
│   ├── app.py              # Main entry point
│   ├── passveurd_app_storage.py
│   └── passveurd_app_config.yaml
├── scripts/                # Scripts and dependency definitions
│   └── requirements.yaml
├── tests/                  # Unit tests
│   ├── __init__.py
│   └── test_password_generator.py
└── README.md
```

## Features

- **Passveurd**: Generate passwords from a secret, domain, and version using PBKDF2 + RC4
- **CryptoPass**: Generate passwords from a secret, username, and URL
- **PIN Config**: Find a version/offset that produces a target PIN for Passveurd
- **Extended character sets**: Lowercase, uppercase, numeric, and special characters
- **Config persistence**: Export/import via JSON or YAML; cookie storage in the app

## Installation

### Option 1: Conda (recommended)

```bash
conda env create -f scripts/requirements.yaml
conda activate cryptography-scripts
```

### Option 2: pip

```bash
pip install streamlit pyyaml extra-streamlit-components
```

## Running the App

From the project root:

```bash
streamlit run App/app.py
```

The app opens in your browser with tabs for Passveurd, PIN Config, and CryptoPass.

## Running Tests

From the project root:

```bash
pytest tests/ -v
```

## Library Usage

```python
from src.PasswordGenerator import Passveurd, CryptoPass, OUTPUT_TYPE, OUTPUT_TYPE_EXTENDED, CHARACTER_TYPE, PasswordMetaData

# Passveurd (domain + version)
pg = Passveurd("example.com", 1, 16, OUTPUT_TYPE.ALPHANUMERICPLUS, metadata=PasswordMetaData())
password = pg.generate_password("your_secret")

# CryptoPass (username + URL)
cp = CryptoPass("user", "https://example.com", 25, PasswordMetaData())
password = cp.generate_password("your_secret")

# Extended character set
output_type = OUTPUT_TYPE_EXTENDED([CHARACTER_TYPE.LOWER, CHARACTER_TYPE.UPPER, CHARACTER_TYPE.NUMERIC])
pg = Passveurd("example.com", 0, 12, output_type, metadata=PasswordMetaData())
password = pg.generate_password("your_secret")
```

## Configuration

Edit `App/passveurd_app_config.yaml` to change default values (page title, cookie key, default state, etc.).

## License

See repository for license information.
