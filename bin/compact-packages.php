#!/usr/bin/env php
<?php
declare(strict_types=1);

/*
 * SPKG is already a single-file format. This retired maintenance command must
 * not convert, inspect, or repackage legacy V14 directories into an active format.
 */
fwrite(STDOUT, "No compaction is required: SPKG packages are stored as single .spkg files.\n");
fwrite(STDOUT, "Legacy V14 directories are unsupported by this command; use release 0.14.1 to export data before upgrading.\n");
exit(0);
