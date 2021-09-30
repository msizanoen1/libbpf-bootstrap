#!/bin/sh
set -e
"${CLANG}" -v -E - < /dev/null 2>&1 |
          sed -En '/<...> search starts here:/,/End of search list./{ s| (/.*)|-idirafter \1|p }'
