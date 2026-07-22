# ==========================================
# NTCF Minor Project - Project Structure Setup
# ==========================================

Write-Host "Creating NTCF project structure..." -ForegroundColor Cyan

# -----------------------------
# Create Directories
# -----------------------------

$directories = @(
    "data",
    "data/raw",
    "data/processed",
    "notebooks",

    "ml",
    "ml/config",
    "ml/preprocessing",
    "ml/feature_selection",
    "ml/models",
    "ml/training",
    "ml/evaluation",
    "ml/artifacts",

    "detection",
    "packet_capture",
    "decision_engine",
    "firewall",
    "database",
    "backend",
    "backend/routes",
    "backend/services",

    "dashboard",
    "dashboard/pages",
    "dashboard/components",
    "dashboard/assets",

    "testing",
    "docs"
)

foreach ($directory in $directories) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

# -----------------------------
# Create Python Package Files
# -----------------------------

$initFiles = @(
    "ml/__init__.py",

    "ml/config/__init__.py",
    "ml/preprocessing/__init__.py",
    "ml/feature_selection/__init__.py",
    "ml/models/__init__.py",
    "ml/training/__init__.py",
    "ml/evaluation/__init__.py",

    "detection/__init__.py",
    "packet_capture/__init__.py",
    "decision_engine/__init__.py",
    "firewall/__init__.py",
    "database/__init__.py",
    "backend/__init__.py",
    "backend/routes/__init__.py",
    "backend/services/__init__.py"
)

foreach ($file in $initFiles) {
    New-Item -ItemType File -Path $file -Force | Out-Null
}

# -----------------------------
# Create ML Files
# -----------------------------

$mlFiles = @(
    "ml/config/columns.py",

    "ml/preprocessing/data_loader.py",
    "ml/preprocessing/cleaner.py",
    "ml/preprocessing/encoder.py",
    "ml/preprocessing/scaler.py",
    "ml/preprocessing/preprocessing_pipeline.py",

    "ml/feature_selection/feature_selection.py",
    "ml/feature_selection/selected_features.json",

    "ml/models/decision_tree_model.py",
    "ml/models/random_forest_model.py",
    "ml/models/svm_model.py",
    "ml/models/model_comparison.py",

    "ml/training/train_models.py",
    "ml/training/save_models.py",

    "ml/evaluation/metrics.py",
    "ml/evaluation/confusion_matrix.py",
    "ml/evaluation/evaluation_report.py"
)

# -----------------------------
# Create Detection Files
# -----------------------------

$projectFiles = @(
    "detection/threat_detector.py",
    "detection/prediction_service.py",
    "detection/confidence_calculator.py",

    "packet_capture/live_capture.py",
    "packet_capture/packet_parser.py",
    "packet_capture/flow_feature_extractor.py",

    "decision_engine/confidence_engine.py",
    "decision_engine/response_actions.py",
    "decision_engine/event_logger.py",

    "firewall/firewall_manager.py",
    "firewall/ip_blocker.py",
    "firewall/ip_unblocker.py",

    "database/schema.sql",
    "database/connection.py",
    "database/models.py",
    "database/repositories.py",

    "backend/app.py",
    "backend/config.py",

    "backend/routes/auth_routes.py",
    "backend/routes/threat_routes.py",
    "backend/routes/detection_routes.py",
    "backend/routes/firewall_routes.py",
    "backend/routes/dashboard_routes.py",

    "backend/services/auth_service.py",
    "backend/services/threat_service.py",
    "backend/services/detection_service.py",
    "backend/services/firewall_service.py",
    "backend/services/dashboard_service.py",

    "dashboard/app.py",

    "dashboard/pages/login.py",
    "dashboard/pages/overview.py",
    "dashboard/pages/threats.py",
    "dashboard/pages/live_monitoring.py",
    "dashboard/pages/blocked_ips.py",
    "dashboard/pages/reports.py",

    "dashboard/components/charts.py",
    "dashboard/components/tables.py",
    "dashboard/components/cards.py",

    "dashboard/assets/style.css",

    "testing/test_preprocessing.py",
    "testing/test_feature_selection.py",
    "testing/test_models.py",
    "testing/test_detection.py",
    "testing/test_decision_engine.py",
    "testing/test_authentication.py",
    "testing/test_api.py",

    "docs/architecture.md",
    "docs/api_documentation.md",
    "docs/database_design.md"
)

# -----------------------------
# Create All Files
# -----------------------------

$allFiles = $mlFiles + $projectFiles

foreach ($file in $allFiles) {
    New-Item -ItemType File -Path $file -Force | Out-Null
}

# -----------------------------
# Create data README
# -----------------------------

New-Item -ItemType File -Path "data/README.md" -Force | Out-Null

# -----------------------------
# Create .gitignore
# -----------------------------

$gitignore = @"
# Python
__pycache__/
*.py[cod]

# Virtual Environment
venv/

# Environment variables
.env

# Jupyter
.ipynb_checkpoints/

# Data
data/raw/*.csv
data/raw/*.txt
data/processed/*

# Models
*.pkl
*.joblib

# VS Code
.vscode/

# OS
.DS_Store
Thumbs.db
"@

Set-Content -Path ".gitignore" -Value $gitignore

# -----------------------------
# Create .env.example
# -----------------------------

New-Item -ItemType File -Path ".env.example" -Force | Out-Null

# -----------------------------
# Create requirements.txt
# -----------------------------

if (Test-Path "venv\Scripts\pip.exe") {
    & "venv\Scripts\pip.exe" freeze | Out-File -Encoding utf8 "requirements.txt"
    Write-Host "requirements.txt created from virtual environment." -ForegroundColor Green
}
else {
    Write-Host "venv not found. Run 'pip freeze > requirements.txt' manually." -ForegroundColor Yellow
    New-Item -ItemType File -Path "requirements.txt" -Force | Out-Null
}

# -----------------------------
# Finish
# -----------------------------

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "NTCF project structure created successfully!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Run the following commands to verify:"
Write-Host "tree /F"
Write-Host ""

Write-Host "Then commit your project:"
Write-Host "git status"
Write-Host "git add ."
Write-Host 'git commit -m "Initial project structure"'
Write-Host "git push origin main"