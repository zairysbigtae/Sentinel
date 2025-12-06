#!/bin/bash
/usr/local/bin/sentinel check-unauthorized-changes &
/usr/local/bin/sentinel analyze-process-behaviors &
wait
