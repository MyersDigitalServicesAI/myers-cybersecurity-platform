#!/bin/bash

# Exit immediately if a command fails
set -e

REPO_URL="https://github.com/MyersDigitalServicesAI/myers-cybersecurity-platform.git"
CLONE_DIR="myers-cybersecurity-platform"
ZIP_FILE="myers-cybersecurity-platform-cleaned-final.zip"

echo "🔄 Cloning the repository..."
git clone $REPO_URL
cd $CLONE_DIR

echo "🔥 Removing existing files (except .git)..."
find . -mindepth 1 -not -name ".git" -exec rm -rf {} +

echo "📦 Unzipping the cleaned project..."
unzip ../$ZIP_FILE
mv myers-cybersecurity-platform-main/* .
rm -rf myers-cybersecurity-platform-main

echo "📁 Staging all files..."
git add .

echo "✅ Committing changes..."
git commit -m "🔥 Replace old code with production-ready cleaned version"

echo "🚀 Force pushing to main branch..."
git push origin main --force

echo "✅ Done! Repository has been updated and pushed."
