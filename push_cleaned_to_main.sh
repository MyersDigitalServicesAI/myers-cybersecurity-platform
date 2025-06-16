#!/bin/bash

set -e

REPO_URL="https://github.com/MyersDigitalServicesAI/myers-cybersecurity-platform.git"
TEMP_DIR="myers-cybersecurity-temp"
ZIP_FILE="myers-cybersecurity-platform-cleaned-final.zip"
BRANCH="main"

echo "🚀 Cloning GitHub repository..."
git clone $REPO_URL $TEMP_DIR
cd $TEMP_DIR

echo "🔥 Removing old files..."
find . -mindepth 1 -not -name ".git" -exec rm -rf {} +

echo "📦 Unzipping cleaned archive..."
unzip ../$ZIP_FILE
mv myers-cybersecurity-platform-main/* .
rm -rf myers-cybersecurity-platform-main

echo "✅ Committing changes..."
git add .
git commit -m "🔥 Full cleanup: secrets via os.environ only, flake8 clean, production-ready"
git push origin $BRANCH --force

echo "✅ Successfully pushed to $REPO_URL on branch $BRANCH"
