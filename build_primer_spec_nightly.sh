#!/bin/sh
# TODO: Make this a cron job

# This script assumes that:
#  - The Primer Spec repo has already been cloned at 'primer-spec-nightly/'
#  - The deployed site will be deployed at 'previews/eecs485staff/primer-spec-nightly/'

echo "Building Primer Spec Nightly\n"

set -Eueox

PREVIEW_URL="https://preview.seshrs.ml/previews/eecs485staff/primer-spec-nightly/"

cd primer-spec-nightly
git reset --hard
git checkout develop
git pull
bundle install
sed -i "\$ s/\$/ (nightly build: $(date '+%Y-%m-%d'))/" VERSION
echo "url: $PREVIEW_URL" >> _config.yml
script/ci-site-preview-build "$PREVIEW_URL"

rm -rf ../previews/eecs485staff/primer-spec-nightly/*
cp -r ./_site/. ../previews/eecs485staff/primer-spec-nightly
cd ..

set +x

echo "Build done. The nightly build can be previewed at $PREVIEW_URL"
