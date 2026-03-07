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
│   ├── requirements.yaml
│   ├── create_env.bat      # Create local env + Jupyter kernel (requires PYTHON_PATH)
│   ├── run_app.bat
│   └── run_tests.bat
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

### Option 1: Batch scripts (Windows, conda)

Set `PYTHON_PATH` to your conda install folder (e.g. `C:\ProgramData\anaconda3`).

```batch
scripts\create_env.bat
```

This creates a local environment in `Cryptography\env\` and registers a Jupyter kernel "Python (Cryptography)" in one step.

### Option 2: Conda manually

```bash
conda env create -f scripts/requirements.yaml --prefix ./env
conda activate ./env
python -m ipykernel install --user --name cryptography-scripts --display-name "Python (Cryptography)"
```

### Option 3: pip

```bash
pip install streamlit pyyaml extra-streamlit-components pytest ipykernel
```

## Running the App

```batch
scripts\run_app.bat
```

Or manually: `streamlit run App/app.py` (with env activated).

The app opens in your browser with tabs for Passveurd, PIN Config, and CryptoPass.

## Running Tests

```batch
scripts\run_tests.bat
```

Or manually: `pytest tests/ -v` (with env activated).

- **test_password_generator.py**: Core library tests (Passveurd, CryptoPass, OUTPUT_TYPE)
- **test_app.py**: App tests (AppTest load, generation logic, storage roundtrip). Skip the UI test with `pytest -m "not streamlit"` if needed.

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
