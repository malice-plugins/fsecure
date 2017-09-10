#!/bin/bash

/etc/init.d/fsaua start
/etc/init.d/fsupdate start
/opt/f-secure/fsav/bin/dbupdate /opt/f-secure/fsdbupdate9.run; exit 0