#!/usr/local/bin/bash

set -x

tag="v$(npm run version --silent)"

if git rev-parse $tag > /dev/null 2>&1;
then
    echo "current tag is already released";
else
    git tag -a $tag -m $tag "${{ github.event.head_commit.message }}"
fi

