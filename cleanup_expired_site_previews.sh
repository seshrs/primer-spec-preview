#!/bin/sh

set -Eueo

NUM_DAYS_TO_EXPIRE=30

# print_modified_date (path: string representing directory)
# Based on: https://stackoverflow.com/a/4997339/5868796
print_modified_date () {
  echo $(find $1 -exec stat \{} --printf="%y\n" \; | 
     sort -n -r | 
     head -n 1)
}

# print_days_difference (date_to_compare)
# Based on: https://stackoverflow.com/a/4679150/5868796
print_days_difference () {
  echo $(( ( $(date +%s) - $(date -d "$1" +%s) ) /(24 * 60 * 60 ) ))
}

# site_preivew_expired (path: string representing directory)
print_site_preview_expired () {
  modified_date="$(print_modified_date $1)"
  days_difference="$(print_days_difference $modified_date)"
  if [ "$days_difference" -gt $NUM_DAYS_TO_EXPIRE ]; then
    echo "true"
  else
    echo "false"
  fi
}

cd previews

for owner in */ ; do
  cd $owner
  for repo in */ ; do
    if [ $repo = "primer-spec-nightly/" ]; then
      continue
    fi
    cd $repo
    for pr in */ ; do
      site_preview_expired="$(print_site_preview_expired $pr)"
      if [ $site_preview_expired = "true" ]; then
        echo "Deleting $owner$repo$pr"
        rm -r $pr
      fi
    done
    cd ..
  done
  cd ..
done

cd ..
