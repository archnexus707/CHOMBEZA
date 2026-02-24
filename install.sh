#!/bin/bash

echo "========================================="
echo "  CHOMBEZA BUG BOUNTY PRO"
echo "  Installation Script"
echo "========================================="
echo ""

# Check Python version
echo "🔍 Checking Python version..."
if command -v python3 &>/dev/null; then
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✅ Python $python_version detected"
else
    echo "❌ Python 3 not found! Please install Python 3.7+"
    exit 1
fi

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📦 Installing requirements..."
pip install -r requirements.txt

# Check if installation was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "========================================="
    echo "✅ CHOMBEZA Installation Complete!"
    echo "========================================="
    echo ""
    echo "To activate the environment:"
    echo "  source venv/bin/activate"
    echo ""
    echo "To start CHOMBEZA GUI:"
    echo "  python main.py"
    echo ""
    echo "To use CHOMBEZA CLI:"
    echo "  python main.py https://target.com --scan-type quick"
    echo ""
    echo "Happy Hunting! 🐞"
else
    echo ""
    echo "❌ Installation failed! Check errors above."
    exit 1
fi